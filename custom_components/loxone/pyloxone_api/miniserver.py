from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import queue
import ssl
import time
import urllib.parse
from base64 import b64decode, b64encode
from collections import namedtuple
from typing import Any, Callable, NoReturn

import httpx
import websockets as wslib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from .message import MessageHeader, parse_message
from .loxtoken import LoxToken

from .const import (
    AES_KEY_SIZE,
    CMD_AUTH_WITH_TOKEN,
    CMD_ENABLE_UPDATES,
    CMD_ENCRYPT_CMD,
    CMD_GET_KEY,
    CMD_GET_KEY_AND_SALT,
    CMD_GET_PUBLIC_KEY,
    CMD_GET_VISUAL_PASSWD,
    CMD_KEY_EXCHANGE,
    CMD_REFRESH_TOKEN,
    CMD_REFRESH_TOKEN_JSON_WEB,
    CMD_REQUEST_TOKEN,
    CMD_REQUEST_TOKEN_JSON_WEB,
    DEFAULT_TOKEN_PERSIST_NAME,
    IV_BYTES,
    KEEP_ALIVE_PERIOD,
    LOXAPPPATH,
    MAX_REFRESH_DELAY,
    SALT_BYTES,
    SALT_MAX_AGE_SECONDS,
    SALT_MAX_USE_COUNT,
    THROTTLE_CHECK_TOKEN_STILL_VALID,
    TIMEOUT,
    TOKEN_PERMISSION,
    CMD_KEEP_ALIVE
)

from .message import LLResponse, TextMessage, ValueStatesTable, TextStatesTable, WeatherStatesTable, Keepalive, DaytimerStatesTable
from .exceptions import LoxoneException, LoxoneHTTPStatusError, LoxoneRequestError
from .wsclient import WSClient

import logging
import traceback

_LOGGER = logging.getLogger(__name__)


async def raise_if_not_200(response: httpx.Response) -> None:
    """An httpx event hook, to ensure that http responses other than 200
    raise an exception"""
    # Loxone response codes are a bit odd. It is not clear whether a response which
    # is not 200 is ever OK (eg it is unclear whether redirect response are issued).
    # json responses also have a "Code" key, but it is unclear whether this is ever
    # different from the http response code. At the moment, we ignore it.
    #
    # And there are references to non-standard codes in the docs (eg a 900 error).
    # At present, treat any non-200 code as an exception.
    if response.status_code != 200:
        if response.is_stream_consumed:
            raise LoxoneHTTPStatusError(
                f"Code {response.status_code}. Miniserver response was {response.text}"
            )
        else:
            raise LoxoneHTTPStatusError(
                f"Miniserver response code {response.status_code}"
            )


def get_public_key(public_key):
    try:
        return PKCS1_v1_5.new(RSA.importKey(public_key))
    except ValueError as exc:
        _LOGGER.error(f"Error creating RSA cipher: {exc}")
        raise LoxoneException(exc)
    return False


Salt = namedtuple("Salt", ["value", "is_new", "previous"])


class _SaltMine:
    """A salt used for encrypting commands."""

    def __init__(self):
        self._salt: str = None
        self._generate_new_salt()

    def _generate_new_salt(self) -> None:
        self._previous = self._salt
        self._salt = get_random_bytes(SALT_BYTES).hex()
        self._timestamp = time.time()
        self._used_count: int = 0
        self._is_new: bool = True
        _LOGGER.debug("Generating a new salt")

    def get_salt(self) -> Salt:
        """Get the current salt in use, or generate a new one if it has expired

        Returns a namedtuple, with attibutes value (the salt as a hex string),
        is_new (a boolean indicating whether this is the first time this
        salt has been returned), and previous (the value of the previous salt, or None).
        """

        self._used_count += 1
        self._is_new = False
        if (
            self._used_count > SALT_MAX_USE_COUNT
            or time.time() - self._timestamp > SALT_MAX_AGE_SECONDS
        ):
            # the salt has expired. Get a new one.
            self._previous = self._salt
            self._generate_new_salt()

        return Salt(self._salt, self._is_new, self._previous)


class LxJsonKeySalt:
    def __init__(self, key=None, salt=None, hash_alg=None):
        self.key = key
        self.salt = salt
        self.hash_alg = hash_alg or "SHA1"


class MiniServer:
    """This class connects to the Loxone Miniserver."""

    def __init__(
        self,
        host=None,
        port=None,
        username=None,
        password=None,
    ):
        """Initialize Miniserver class."""
        self._host: str = host
        self._port: int = port
        self._username: str = username
        self._password: str = password

        self._use_tls = False
        self._https_status = None
        self._tls_check_hostname: bool = True
        self._local = None
        self._iv = get_random_bytes(IV_BYTES)
        self._key = get_random_bytes(AES_KEY_SIZE)
        self._public_key: str = None
        self._session_key = None
        self._saltmine = _SaltMine()
        self._current_key_and_salt = None
        self._token = None

        self.message_body = None
        self.message_header = None

        self.json = None
        self.snr: str = ""

        self.ready = asyncio.Event()

        self.version: str = ""  # a string, eg "12.0.1.2"
        self._version: list[int] = []  # a list of ints eg [12,0,1,2]
        self._https_status: int | None = (
            None  # None = no TLS, 1 = TLS available, 2 = cert expired
        )
        self.loop = None
        self.wsclient = None
        self.async_connection_status_callback = None
        self.running_task = []

    def connect(self, loop, connection_status):
        """Connect to the miniserver."""
        self.loop = loop
        self.async_connection_status_callback = connection_status

        self.wsclient = WSClient(
            self.loop, self._host,
            self._port,
            self._username,
            self._password,
            self._use_tls,
            self.async_session_handler,
            self.async_message_handler,
        )
        self.wsclient.start()

        _LOGGER.debug("Finished connect")

    def async_session_handler(self, state):
        _LOGGER.debug("async_session_handler")
        _LOGGER.debug("state: {0}".format(state))
        if state == "running":
            command = f"{CMD_KEY_EXCHANGE}{self._session_key.decode()}"
            self.wsclient.send(command)

    def _encrypt(self, command: str) -> str:
        # if not self._encryption_ready:
        #     return command
        salt = self._saltmine.get_salt()
        if salt.is_new:
            s = f"nextSalt/{salt.previous}/{salt.value}/{command}\x00"
        else:
            s = f"salt/{salt.value}/{command}\x00"

        padded_s = Padding.pad(bytes(s, "utf-8"), 16)
        aes_cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        encrypted = aes_cipher.encrypt(padded_s)
        encoded = b64encode(encrypted)
        encoded_url = urllib.parse.quote(encoded.decode("utf-8"))
        return CMD_ENCRYPT_CMD + encoded_url

    def _hash_credentials(self, key_salt: LxJsonKeySalt):
        try:
            pwd_hash_str = f"{self._password}:{key_salt.salt}"
            if key_salt.hash_alg == "SHA1":
                m = hashlib.sha1()
            elif key_salt.hash_alg == "SHA256":
                m = hashlib.sha256()
            else:
                _LOGGER.error(f"Unrecognised hash algorithm: {key_salt.hash_alg}")
                return None

            m.update(pwd_hash_str.encode("utf-8"))
            pwd_hash = m.hexdigest().upper()
            pwd_hash = f"{self._username}:{pwd_hash}"

            if key_salt.hash_alg == "SHA1":
                digester = HMAC.new(
                    bytes.fromhex(key_salt.key), pwd_hash.encode("utf-8"), SHA1
                )
            elif key_salt.hash_alg == "SHA256":
                digester = HMAC.new(
                    bytes.fromhex(key_salt.key), pwd_hash.encode("utf-8"), SHA256
                )
            _LOGGER.debug("hash_credentials successfully...")
            return digester.hexdigest()
        except ValueError:
            _LOGGER.error("error hash_credentials...")
            return None

    def _has_token(self, key):
        if self._token.hash_alg == "SHA1":
            digester = HMAC.new(
                bytes.fromhex(key),
                self._token.token.encode("utf-8"),
                SHA1,
            )
        elif self._token.hash_alg == "SHA256":
            digester = HMAC.new(
                bytes.fromhex(key),
                self._token.token.encode("utf-8"),
                SHA256,
            )
        return digester.hexdigest()

    def _decrypt(self, command: str) -> bytes:
        """AES decrypt a command returned by the miniserver."""
        # control will be in the form:
        # "jdev/sys/enc/CHG6k...A=="
        # Encrypted strings returned by the miniserver are not %encoded (even
        # if they were when sent to the miniserver )
        remove_text = "jdev/sys/enc/"
        enc_text = (
            command[len(remove_text) :] if command.startswith(remove_text) else command
        )
        decoded = b64decode(enc_text)
        aes_cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        decrypted = aes_cipher.decrypt(decoded)
        unpadded = Padding.unpad(decrypted, 16)
        # The miniserver seems to terminate the text with a zero byte
        return unpadded.rstrip(b"\x00")

    def async_message_handler(self, message, is_binary):
        if is_binary and len(message) == 8 and message[0] == 3:
            if len(message) == 8 and message[0] == 3:
                self.message_header = MessageHeader(message)

        else:
            if is_binary:
                mess_obj = parse_message(message, self.message_header.message_type)
            else:
                if message.startswith("{"):
                    mess_obj = parse_message(message, self.message_header.message_type)
                else:
                    raise NotImplementedError("Decryption not implemented yet")

            if isinstance(mess_obj, TextMessage) and "keyexchange" in mess_obj.message:
                # Wheather load token or get token with getkey2
                self._token = LoxToken(
                    token_dir="",
                    token_filename=DEFAULT_TOKEN_PERSIST_NAME,
                )

                if self._token.is_loaded and self._token.seconds_to_expire() > 300:
                    _LOGGER.debug("Token successfully loaded from file")
                    command = f"{CMD_GET_KEY}"
                    self.wsclient.send(self._encrypt(command))
                else:
                    _LOGGER.debug("Token could not load or expired.")
                    command = f"{CMD_GET_KEY_AND_SALT}{self._username}"
                    self.wsclient.send(self._encrypt(command))

            elif isinstance(mess_obj, TextMessage) and "getkey2" in mess_obj.message:
                # Response of CMD_GET_KEY_AND_SALT. Request a new Token
                self._current_key_and_salt = LxJsonKeySalt(
                    mess_obj.value_as_dict["key"],
                    mess_obj.value_as_dict["salt"],
                    mess_obj.value_as_dict.get("hashAlg", None),
                )
                new_hash = self._hash_credentials(self._current_key_and_salt)
                if new_hash is None:
                    return
                if self._version < [10, 2]:
                    # 'jdev/sys/gettoken/507a4c8d1c89d7bfb35ab7aa34a3865ff8e3b738/dev/2/edfc5f9a-df3f-4cad-9dddcdc42c732be2/pyloxone_api'
                    command = f"{CMD_REQUEST_TOKEN}{new_hash}/{self._username}/{TOKEN_PERMISSION}/edfc5f9a-df3f-4cad-9dddcdc42c732be2/pyloxone_api"
                else:
                    # 'jdev/sys/getjwt/6b30234557c62ee7b0509698ce4857dabcd703fc/dev/2/edfc5f9a-df3f-4cad-9dddcdc42c732be2/pyloxone_api'
                    command = f"{CMD_REQUEST_TOKEN_JSON_WEB}{new_hash}/{self._username}/{TOKEN_PERMISSION}/edfc5f9a-df3f-4cad-9dddcdc42c732be2/pyloxone_api"
                self.wsclient.send(self._encrypt(command))

            elif isinstance(mess_obj, TextMessage) and "getkey" in mess_obj.message:
                # Response of CMD_GET_KEY. Token still valid and loaded
                key = mess_obj.value
                if key != "":
                    token_hash = self._has_token(key)
                    command = f"{CMD_AUTH_WITH_TOKEN}{token_hash}/{self._username}"
                    self.wsclient.send(self._encrypt(command))

            elif isinstance(mess_obj, TextMessage) and ("gettoken" in mess_obj.message or "getjwt" in mess_obj.message):
                _LOGGER.debug('Process gettoken response')
                response = LLResponse(mess_obj.message)
                self._token.token = response.value_as_dict["token"]
                self._token.valid_until = response.value_as_dict["validUntil"]
                self._token.hash_alg = self._current_key_and_salt.hash_alg
                token_safe_result = self._token.save()
                if token_safe_result:
                    _LOGGER.debug("Token safed.")
                command = f"{CMD_ENABLE_UPDATES}"
                self.wsclient.send(self._encrypt(command))

            elif isinstance(mess_obj, TextMessage) and "authwithtoken" in mess_obj.message:
                _LOGGER.debug("Authentification with token successfully")
                command = f"{CMD_ENABLE_UPDATES}"
                self.wsclient.send(self._encrypt(command))
                keep_alive_task = self.loop.create_task(self.keep_alive())
                self.running_task.append(keep_alive_task)

            elif isinstance(mess_obj, TextMessage) and "enablebinstatusupdate" in mess_obj.message:
                _LOGGER.debug('Process enablebinstatusupdate response')

            elif isinstance(mess_obj, TextMessage) and "dev/sps/io/" in mess_obj.message:
                _LOGGER.debug('Process io response')

            elif isinstance(mess_obj, ValueStatesTable):
                print("Got ValueStatesTable")
                print(mess_obj.as_dict())

            elif isinstance(mess_obj, TextStatesTable):
                print("Got TextStatesTable")
                print(mess_obj.as_dict())

            elif isinstance(mess_obj, Keepalive):
                print("Got Keepalive")
                print(mess_obj.as_dict())

            elif isinstance(mess_obj, WeatherStatesTable):
                print("Got WeatherStatesTable")
                print(mess_obj.as_dict())

            elif isinstance(mess_obj, DaytimerStatesTable):
                print("Got DaytimerStatesTable")
                print(mess_obj.as_dict())

            else:
                _LOGGER.debug('Process <UNKNOWN> response')

                #_LOGGER.debug("header: {0}-{1}-{2}".format(self.message_header.payload[0], self.message_header.payload[1], self.message_header.payload[2]))
                #_LOGGER.debug("response: " + self.decrypt_message(message))

    async def get_json(self) -> bool:
        """Obtain basic info from the miniserver"""
        # All initial http/https requests are carried out here, for simplicity. They
        # can all use the same httpx.AsyncClient instance. Any non-200 response from
        # the miniserver will cause an exception to be raised, via the event_hook
        scheme = "https" if self._use_tls else "http"
        auth = None

        if self._port == "80":
            _base_url = f"{scheme}://{self._host}"
        else:
            _base_url = f"{scheme}://{self._host}:{self._port}"

        if self._username is not None and self._password is not None:
            auth = (self._username, self._password)

        client = httpx.AsyncClient(
            auth=auth,
            base_url=_base_url,
            verify=self._tls_check_hostname,
            timeout=TIMEOUT,
            event_hooks={"response": [raise_if_not_200]},
        )

        try:
            api_resp = await client.get("/jdev/cfg/apiKey")
            value = LLResponse(api_resp.text).value
            # The json returned by the miniserver is invalid. It contains " and '.
            # We need to normalise it
            value = json.loads(value.replace("'", '"'))
            self._https_status = value.get("httpsStatus")
            self.version = value.get("version")
            self._version = (
                [int(x) for x in self.version.split(".")] if self.version else []
            )
            self.snr = value.get("snr")
            self._local = value.get("local", True)
            if not self._local:
                _base_url = str(api_resp.url).replace("/jdev/cfg/apiKey", "")
                client = httpx.AsyncClient(
                    auth=auth,
                    base_url=_base_url,
                    verify=self._tls_check_hostname,
                    timeout=TIMEOUT,
                    event_hooks={"response": [raise_if_not_200]},
                )

            # Get the structure file
            loxappdata = await client.get(LOXAPPPATH)
            status = loxappdata.status_code
            if status == 200:
                self.json = loxappdata.json()
                self.json[
                    "softwareVersion"
                ] = self._version  # FIXME Legacy use only. Need to fix pyloxone
            else:
                return False
            # Get the public key
            pk_data = await client.get(CMD_GET_PUBLIC_KEY)
            pk = LLResponse(pk_data.text).value
            # Loxone returns a certificate instead of a key, and the certificate is not
            # properly PEM encoded because it does not contain newlines before/after the
            # boundaries. We need to fix both problems. Proper PEM encoding requires 64
            # char line lengths throughout, but Python does not seem to insist on this.
            # If, for some reason, no certificate is returned, _public_key will be an
            # empty string.
            self._public_key = pk.replace(
                "-----BEGIN CERTIFICATE-----", "-----BEGIN PUBLIC KEY-----\n"
            ).replace("-----END CERTIFICATE-----", "\n-----END PUBLIC KEY-----\n")

        # Handle errors. An http error getting any of the required data is
        # probably fatal, so log it and raise it for handling elsewhere. Other errors
        # are (hopefully) unlikely, but are not handled here, so will be raised
        # normally.
        except httpx.RequestError as exc:
            _LOGGER.error(
                f'An error "{exc}" occurred while requesting {exc.request.url!r}.'
            )
            raise LoxoneRequestError(exc) from None
        except LoxoneHTTPStatusError as exc:
            _LOGGER.error(exc)
            raise LoxoneHTTPStatusError(exc) from None
        except Exception:
            traceback.print_exc()
        finally:
            # Async httpx client must always be closed
            await client.aclose()
            return True

    async def async_setup(self) -> bool:
        json_res = await self.get_json()
        if not json_res:
            _LOGGER.error("Error getting public key and config json.")
            return False

        rsa_cipher = get_public_key(self._public_key)
        if not rsa_cipher:
            return False

        aes_key = self._key.hex()
        iv = self._iv.hex()
        try:
            session_key = f"{aes_key}:{iv}".encode("utf-8")
            self._session_key = b64encode(rsa_cipher.encrypt(session_key))
            _LOGGER.debug("generate_session_key successfully...")
        except ValueError as exc:
            _LOGGER.error(f"Error generating session key: {exc}")
            raise LoxoneException(exc) from None
        return True

    async def keep_alive(self):
        while self.loop.is_running():
            await asyncio.sleep(KEEP_ALIVE_PERIOD)
            self.wsclient.send(CMD_KEEP_ALIVE)

'''

class MiniServer2:
    def __init__(self, hass, config_entry) -> None:
        self.hass = hass
        self.config_entry = config_entry
        self.api = None
        self.callback = None
        self.entities = {}
        self.listeners = []

    @callback
    def async_signal_new_device(self, device_type) -> str:
        """Gateway specific event to signal new device."""
        new_device = {
            NEW_GROUP: f"loxone_new_group_{self.miniserverid}",
            NEW_LIGHT: f"loxone_new_light_{self.miniserverid}",
            NEW_SCENE: f"loxone_new_scene_{self.miniserverid}",
            NEW_SENSOR: f"loxone_new_sensor_{self.miniserverid}",
            NEW_COVERS: f"loxone_new_cover_{self.miniserverid}",
        }
        return new_device[device_type]

    @callback
    async def async_loxone_callback(self, message) -> None:
        """Handle event from pyloxone-api."""
        self.hass.async_fire(EVENT, message)

    @property
    def serial(self):
        try:
            return self.api.json["msInfo"]["serialNr"]
        except:
            return None

    @property
    def name(self):
        try:
            return self.api.json["msInfo"]["msName"]
        except:
            return None

    @property
    def software_version(self):
        try:
            return ".".join([str(x) for x in self.api.json["softwareVersion"]])
        except:
            return None

    @property
    def miniserver_type(self):
        try:
            return self.api.json["msInfo"]["miniserverType"]
        except:
            return None

    @callback
    async def shutdown(self, event) -> None:
        await self.api.stop()

    async def async_setup(self) -> bool:
        try:
            self.api = LoxAPI(
                host=self.config_entry.options[CONF_HOST],
                port=self.config_entry.options[CONF_PORT],
                user=self.config_entry.options[CONF_USERNAME],
                password=self.config_entry.options[CONF_PASSWORD],
            )
            await self.api.getJson()
            # self.api.config_dir = get_default_config_dir()
            self.api.config_dir = ""
            await self.api.async_init()

        except ConnectionError:
            _LOGGER.error("Error connecting to loxone miniserver. See error log.")
            return False
        except:
            traceback.print_exc()
        return True

    async def async_set_callback(self, message_callback):
        self.api.message_call_back = message_callback

    async def start_loxone(self, event):
        await self.api.start()

    async def stop_loxone(self, event):
        _ = await self.api.stop()
        _LOGGER.debug(_)

    async def listen_loxone_send(self, event):
        """Listen for change Events from Loxone Components"""
        try:
            if event.event_type == SENDDOMAIN and isinstance(event.data, dict):
                value = event.data.get(ATTR_VALUE, DEFAULT)
                device_uuid = event.data.get(ATTR_UUID, DEFAULT)
                await self.api.send_websocket_command(device_uuid, value)

            elif event.event_type == SECUREDSENDDOMAIN and isinstance(event.data, dict):
                value = event.data.get(ATTR_VALUE, DEFAULT)
                device_uuid = event.data.get(ATTR_UUID, DEFAULT)
                code = event.data.get(ATTR_CODE, DEFAULT)
                await self.api.send_secured__websocket_command(device_uuid, value, code)

        except ValueError:
            traceback.print_exc()

    async def handle_websocket_command(self, call):
        """Handle websocket command services."""
        value = call.data.get(ATTR_VALUE, DEFAULT)
        device_uuid = call.data.get(ATTR_UUID, DEFAULT)
        await self.api.send_websocket_command(device_uuid, value)

    async def async_update_device_registry(self) -> None:
        device_registry = await self.hass.helpers.device_registry.async_get_registry()

        # Host device
        # device_registry.async_get_or_create(
        #     config_entry_id=self.config_entry.entry_id,
        #     connections={
        #         (CONNECTION_NETWORK_MAC, self.config_entry.options[CONF_HOST])
        #     },
        # )

        # Miniserver service
        device_registry.async_get_or_create(
            config_entry_id=self.config_entry.entry_id,
            connections={
                (CONNECTION_NETWORK_MAC, self.config_entry.options[CONF_HOST])
            },
            identifiers={(DOMAIN, self.serial)},
            name=self.name,
            manufacturer="Loxone",
            sw_version=self.software_version,
            model=get_miniserver_type(self.miniserver_type),
        )

    @property
    def host(self) -> str:
        """Return the host of the miniserver."""
        return self.config_entry.data[CONF_HOST]

    @property
    def miniserverid(self) -> str:
        """Return the unique identifier of the Miniserver."""
        return self.config_entry.unique_id
'''
