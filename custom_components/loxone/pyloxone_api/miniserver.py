from __future__ import annotations

import asyncio
import hashlib
import binascii
import json
import logging
import queue
import time
import traceback
import datetime
import urllib.parse
import urllib.request as req
from base64 import b64decode, b64encode
from collections import namedtuple
from typing import Optional

import httpx
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

from .const import (
    AES_KEY_SIZE,
    CMD_AUTH_WITH_TOKEN,
    CMD_CHECK_TOKEN,
    CMD_ENABLE_UPDATES,
    CMD_ENCRYPT_CMD,
    CMD_GET_KEY,
    CMD_GET_KEY_AND_SALT,
    CMD_GET_PUBLIC_KEY,
    CMD_GET_VISUAL_PASSWD,
    CMD_KEEP_ALIVE,
    CMD_KEY_EXCHANGE,
    CMD_REFRESH_TOKEN,
    CMD_KILL_TOKEN,
    CMD_REFRESH_TOKEN_JSON_WEB,
    CMD_REQUEST_TOKEN,
    CMD_REQUEST_TOKEN_JSON_WEB,
    DEFAULT_TOKEN_PERSIST_NAME,
    IV_BYTES,
    KEEP_ALIVE_PERIOD,
    LOXAPPPATH,
    SALT_BYTES,
    SALT_MAX_AGE_SECONDS,
    SALT_MAX_USE_COUNT,
    THROTTLE_CHECK_TOKEN_STILL_VALID,
    TIMEOUT,
    TOKEN_PERMISSION, TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY,
)
from .exceptions import LoxoneException, LoxoneHTTPStatusError, LoxoneRequestError
from .loxtoken import LoxToken
from .message import (
    DaytimerStatesTable,
    Keepalive,
    LLResponse,
    MessageHeader,
    TextMessage,
    TextStatesTable,
    ValueStatesTable,
    WeatherStatesTable,
    parse_message,
)
from .wsclient import STATE_RUNNING, WSClient

_LOGGER = logging.getLogger(__name__)

_LOXONE_ALLOWED_STATUS_CODES = {200, 307}


async def raise_if_not_200(response: httpx.Response) -> None:
    """An httpx event hook, to ensure that http responses other than 200
    raise an exception"""
    # Loxone response codes are a bit odd.only 200 and 307 (from dns) are ok
    # json responses also have a "Code" key, but it is unclear whether this is ever
    # different from the http response code. At the moment, we ignore it.
    #
    # And there are references to non-standard codes in the docs (eg a 901 error).
    # At present, treat any non-200 or non redirect code as an exception.
    if response.status_code not in _LOXONE_ALLOWED_STATUS_CODES:
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


Salt = namedtuple("Salt", ["value", "is_new", "previous"])


class _SaltMine:
    """A salt used for encrypting commands."""

    def __init__(self):
        self._salt: Optional[str] = None
        self._generate_new_salt()
        self._is_new: bool = True
        self._previous = self._salt

    def _generate_new_salt(self) -> None:

        def time_elapsed_in_seconds():
            return int(round(time.time()))

        self._salt = get_random_bytes(SALT_BYTES)
        self._salt = binascii.hexlify(self._salt).decode("utf-8")
        self._salt = req.pathname2url(self._salt)
        self._timestamp = time_elapsed_in_seconds()
        self._used_count: int = 0
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
            self._is_new = True

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
            url: str,
            username: str = None,
            password: str = None,
    ):
        """Initialize Miniserver class."""
        self.url = url.rstrip("/")
        self._username: str = username
        self._password: str = password

        self._https_status = None
        self._tls_check_hostname: bool = True
        self._local = None
        self._iv = get_random_bytes(IV_BYTES)
        self._key = get_random_bytes(AES_KEY_SIZE)
        self._public_key: Optional[str] = None
        self._session_key = None
        self._salt_mine = _SaltMine()
        self._current_key_and_salt = None
        self._token = None
        self._token_hash = None

        self.message_body = None
        self.message_header = None
        self.message_call_back = None

        self.json: Optional[dict] = None
        self.snr: str = ""

        self.ready = asyncio.Event()

        self.version: str = ""  # a string, eg "12.0.1.2"
        self._version: list[int] = []  # a list of ints eg [12,0,1,2]
        self._https_status: int | None = (
            None  # None = no TLS, 1 = TLS available, 2 = cert expired
        )
        self.loop = None
        self.wsclient: Optional[WSClient] = None
        self.async_connection_status_callback = None
        self._pending = []
        self._get_key_queue = queue.Queue(maxsize=10)
        self._secured_queue = queue.Queue(maxsize=1)

    @property
    def loxone_config(self):
        return self.json

    def async_set_callback(self, message_callback):
        self.message_call_back = message_callback

    async def stop(self):  # maybe this can be a asynchronous context manager (with connecct being __aenter)
        await self.wsclient.stop()
        for task in self._pending:
            task.cancel()

    def connect(self, loop, connection_status):
        """Connect to the miniserver."""
        self.loop = loop
        self.async_connection_status_callback = connection_status

        self.wsclient = WSClient(
            self.loop,
            self.url,
            self._username,
            self._password,
            self.async_session_handler,
            self.async_message_handler,
        )
        running_task = self.wsclient.start()
        if running_task:
            self._pending.append(running_task)
        _LOGGER.debug("Finished connect")

    @property
    def miniserver_type(self):
        try:
            return self.json["msInfo"]["miniserverType"]
        except:
            return None

    def async_session_handler(self, state):
        _LOGGER.debug("async_session_handler")
        _LOGGER.debug("state: {0}".format(state))
        if state == STATE_RUNNING:
            command = f"{CMD_KEY_EXCHANGE}{self._session_key.decode()}"
            self.wsclient.send(command)

    def send_command(self):
        print("Send command")

    def add_async_command_with_get_key2(self, coro):

        try:
            task = self.loop.create_task(self.wsclient.ws.send_str(f"{CMD_GET_KEY}"))
            task.add_done_callback(coro)
        except Exception as err:
            _LOGGER.error("send Error {0}".format(err))

        # task = self.loop.create_task(self.wsclient.ws.send_str(f"{CMD_GET_KEY}"))
        # #task = asyncio.create_task(self.wsclient.ws.send_str(f"{CMD_GET_KEY}"))
        # task.add_done_callback(self.send_command(task.result))

        #rest = asyncio.run(task)
        print("D")
        # #self.loop.create_task(self.ws.send_str(message))
        # loop = asyncio.get_event_loop()
        # #future = asyncio.run_coroutine_threadsafe(self.wsclient.ws.send_str(f"{CMD_GET_KEY}"), loop)
        # future = asyncio.run_coroutine_threadsafe(coro, loop)
        # try:
        #     result = future.result(3)
        # except concurrent.futures.TimeoutError:
        #     print('The coroutine took too long, cancelling the task...')
        #     future.cancel()
        # except Exception as exc:
        #     print(f'The coroutine raised an exception: {exc!r}')
        # else:
        #     print(f'The coroutine returned: {result!r}')
        #self._get_key_queue.put(coro)
        #self.wsclient.send(f"{CMD_GET_KEY}")

    def send(self, command):
        self.wsclient.send(command)

    def send_secure(self, secure_queue_para):
        self._secured_queue.put(secure_queue_para)
        command = f"{CMD_GET_VISUAL_PASSWD}{self._username}"
        enc_command = self._encrypt(command)
        self.wsclient.send(enc_command)

    def _encrypt(self, command: str) -> str:
        # if not self._encryption_ready:
        #     return command
        salt = self._salt_mine.get_salt()
        if salt.is_new:
            s = f"nextSalt/{salt.previous}/{salt.value}/{command}\0"
        else:
            s = f"salt/{salt.value}/{command}\0"

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

            # # Todo this is here repeated multiple times (and only hash alg changes).. abstract it
            if key_salt.hash_alg == "SHA1":
                digester = HMAC.new(
                    bytes.fromhex(key_salt.key), pwd_hash.encode("utf-8"), SHA1
                )
            elif key_salt.hash_alg == "SHA256":
                digester = HMAC.new(
                    bytes.fromhex(key_salt.key), pwd_hash.encode("utf-8"), SHA256
                )
            else:
                raise LoxoneException("unknown SHA ALG")
            _LOGGER.debug("hash_credentials successfully...")
            return digester.hexdigest()
        except ValueError:
            _LOGGER.error("error hash_credentials...")
            return None

    def _hash_token(self, key):
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
        else:
            raise LoxoneException("unknown SHA ALG")
        return digester.hexdigest()

    def _decrypt(self, command: str) -> bytes:
        """AES decrypt a command returned by the miniserver."""
        # control will be in the form:
        # "jdev/sys/enc/CHG6k...A=="
        # Encrypted strings returned by the miniserver are not %encoded (even
        # if they were when sent to the miniserver )
        remove_text = "jdev/sys/enc/"
        enc_text = (
            command[len(remove_text):] if command.startswith(remove_text) else command
        )
        decoded = b64decode(enc_text)
        aes_cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
        decrypted = aes_cipher.decrypt(decoded)
        unpadded = Padding.unpad(decrypted, 16)
        # The miniserver seems to terminate the text with a zero byte
        return unpadded.rstrip(b"\x00")

    async def async_message_handler(self, message, is_binary):
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

            if hasattr(mess_obj, "control") and mess_obj.control.find("/enc/") > -1:
                mess_obj.control = self._decrypt(mess_obj.control)

            if isinstance(mess_obj, TextMessage) and "keyexchange" in mess_obj.message:
                # Wheather load token or get token with getkey2
                self._token = LoxToken(
                    token_dir="",
                    token_filename=DEFAULT_TOKEN_PERSIST_NAME,
                )

                if self._token.is_loaded and self._token.seconds_to_expire() > 300:
                    _LOGGER.debug("Token successfully loaded from file")
                    self.wsclient.send(self._encrypt(f"{CMD_GET_KEY}"))
                else:
                    _LOGGER.debug("Token could not load or expired.")
                    self.wsclient.send(
                        self._encrypt(f"{CMD_GET_KEY_AND_SALT}{self._username}")
                    )

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
                    token_hash = self._hash_token(key)
                    if self._token_hash is None:
                        self._token_hash = token_hash
                        command = (
                            f"{CMD_AUTH_WITH_TOKEN}{self._token_hash}/{self._username}"
                        )
                        self.wsclient.send(self._encrypt(command))
                    else:
                        self._token_hash = token_hash
                        try:
                            if not self._get_key_queue.empty():
                                item = await self._get_key_queue.get()
                                if not self._get_key_queue.empty():
                                    self.wsclient.send(f"{CMD_GET_KEY}")
                        except:
                            traceback.print_exc()
                            # maybe put this as _logger.exception?
                            _LOGGER.debug("msg handler failiure", exc_info=True)

            elif isinstance(mess_obj, TextMessage) and (
                    "gettoken" in mess_obj.message or "getjwt" in mess_obj.message
            ):
                _LOGGER.debug("Process gettoken response")
                response = LLResponse(mess_obj.message)
                self._token.token = response.value_as_dict["token"]
                self._token.valid_until = response.value_as_dict["validUntil"]
                self._token.hash_alg = self._current_key_and_salt.hash_alg
                token_safe_result = self._token.save()
                if token_safe_result:
                    _LOGGER.debug("Token saved.")
                self.wsclient.send(self._encrypt(f"{CMD_ENABLE_UPDATES}"))

            elif isinstance(mess_obj, TextMessage) and (
                    "refreshtoken" in mess_obj.message or "refreshjwt" in mess_obj.message
            ):
                _LOGGER.debug("Process refreshtoken response")
                response = LLResponse(mess_obj.message)
                self._token.token = response.value_as_dict["token"]
                self._token.valid_until = response.value_as_dict["validUntil"]
                token_safe_result = self._token.save()
                if token_safe_result:
                    _LOGGER.debug("Token saved.")

            elif (
                    isinstance(mess_obj, TextMessage)
                    and "authwithtoken" in mess_obj.message
            ):
                if mess_obj.code == 200:
                    _LOGGER.debug("Authentification with token successfully")
                    command = f"{CMD_ENABLE_UPDATES}"
                    self.wsclient.send(self._encrypt(command))
                    keep_alive_task = self.loop.create_task(self._keep_alive())
                    self._pending.append(keep_alive_task)
                    # check_still_valid = self.loop.create_task(
                    #     self.check_token_still_valid()
                    # )
                    # self._pending.append(check_still_valid)
                else:
                    _LOGGER.debug(
                        "Authentification with token not successfully. Old token will be deleted."
                    )
                    self._token.delete()
            elif (
                    isinstance(mess_obj, TextMessage)
                    and "enablebinstatusupdate" in mess_obj.message
            ):
                _LOGGER.debug("Process enablebinstatusupdate response")

            elif isinstance(mess_obj, TextMessage) and "checktoken" in mess_obj.message:
                _LOGGER.debug("Process checktoken response")
                if isinstance(mess_obj, TextMessage) and mess_obj.code == 200:
                    _LOGGER.debug(f"Token is verified for {self._username}.")

                    def get_seconds_to_expire(vaild_until):
                        dt = datetime.datetime.strptime("1.1.2009", "%d.%m.%Y")
                        try:
                            start_date = int(dt.strftime("%s"))
                        except:
                            start_date = int(dt.timestamp())
                        start_date = int(start_date) + vaild_until
                        return start_date - int(round(time.time()))

                    valid_until = mess_obj.value_as_dict.get("validUntil", None)
                    if valid_until:
                        sec = get_seconds_to_expire(valid_until)
                        if sec < TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY:
                            self.refresh_token()

                elif isinstance(mess_obj, TextMessage) and mess_obj.code == 401:
                    raise LoxoneException("401 - UNAUTHORIZED for check token.")
                elif isinstance(mess_obj, TextMessage) and mess_obj.code == 400:
                    raise LoxoneException("400 - BAD_REQUEST for check token.")
                # Like an 401 but that when the token is no longer valid.
                elif isinstance(mess_obj, TextMessage) and mess_obj.code == 477:
                    self.refresh_token()

            elif isinstance(mess_obj, TextMessage) and "kill" in mess_obj.message:
                _LOGGER.debug("Process kill_token response")

            elif (
                    isinstance(mess_obj, TextMessage) and "getvisusalt" in mess_obj.message
            ):
                if mess_obj.code == 200:
                    mess_obj_dict = mess_obj.value_as_dict
                    key = mess_obj_dict.get("key", None)
                    salt = mess_obj_dict.get("salt", None)
                    hash_alg = mess_obj_dict.get("hashAlg", None)
                    visual_key_and_salt = LxJsonKeySalt(key, salt, hash_alg)
                    while not self._secured_queue.empty():
                        device_uuid, value, code = self._secured_queue.get()
                        pwd_hash_str = code + ":" + visual_key_and_salt.salt
                        if visual_key_and_salt.hash_alg == "SHA1":
                            m = hashlib.sha1()
                        elif visual_key_and_salt.hash_alg == "SHA256":
                            m = hashlib.sha256()
                        m.update(pwd_hash_str.encode("utf-8"))
                        pwd_hash = m.hexdigest().upper()

                        if visual_key_and_salt.hash_alg == "SHA1":
                            digester = HMAC.new(
                                binascii.unhexlify(visual_key_and_salt.key),
                                pwd_hash.encode("utf-8"),
                                SHA1,
                            )
                        elif visual_key_and_salt.hash_alg == "SHA256":
                            digester = HMAC.new(
                                binascii.unhexlify(visual_key_and_salt.key),
                                pwd_hash.encode("utf-8"),
                                SHA256,
                            )
                        else:
                            raise LoxoneException("unknown SHA ALG")
                        command = "jdev/sps/ios/{}/{}/{}".format(
                            digester.hexdigest(), device_uuid, value
                        )
                        self.wsclient.send(command)

            elif (
                    isinstance(mess_obj, TextMessage) and "dev/sps/io/" in mess_obj.message
            ):
                _LOGGER.debug("Process io response")
                if self.message_call_back:
                    await self.message_call_back(mess_obj.message)

            elif (
                    isinstance(mess_obj, TextMessage) and "dev/sps/ios/" in mess_obj.message
            ):
                _LOGGER.debug("Process ios response")
                if self.message_call_back:
                    await self.message_call_back(mess_obj.message)

            elif isinstance(mess_obj, ValueStatesTable):
                if self.message_call_back:
                    await self.message_call_back(mess_obj.as_dict())

            elif isinstance(mess_obj, TextStatesTable):
                if self.message_call_back:
                    await self.message_call_back(mess_obj.as_dict())

            elif isinstance(mess_obj, Keepalive):
                _LOGGER.debug("Got Keepalive")

            elif isinstance(mess_obj, WeatherStatesTable):
                _LOGGER.debug("Got WeatherStatesTable")

            elif isinstance(mess_obj, DaytimerStatesTable):
                _LOGGER.debug("Got DaytimerStatesTable")
                # Todo implement this
            else:
                _LOGGER.debug("Process <UNKNOWN> response")
                _LOGGER.debug(mess_obj)
                _LOGGER.debug(mess_obj.message)

    async def _get_json(self) -> bool:
        """Obtain basic info from the miniserver
        this method is unsafe if multiple async call are being made
        """
        # All initial http/https requests are carried out here, for simplicity. They
        # can all use the same httpx.AsyncClient instance. Any non-200 response from
        # the miniserver will cause an exception to be raised, via the event_hook
        auth = None
        if self._username is not None and self._password is not None:
            auth = (self._username, self._password)

        try:
            async with httpx.AsyncClient(
                    auth=auth,
                    base_url=self.url,
                    verify=self._tls_check_hostname,
                    timeout=TIMEOUT,
                    event_hooks={"response": [raise_if_not_200]},
            ) as client:  # use only one client managed with context manager and change base url if needed
                # sniff DNS (internally you should not get 307 unless you are being redirected)
                api_resp: httpx.Response = await client.get("")  # get base page to check if we are getting redirected
                if api_resp.status_code == 307:  # redirected. change url
                    self.url = str(api_resp.next_request.url).rstrip("/")
                    client.base_url = self.url
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
            _LOGGER.debug("During getting json something went wrong", exc_info=True)
            traceback.print_exc()
        finally:
            if self.json:
                # this is only getting serialized when debug level is set
                _LOGGER.debug("successfully downloaded following "
                              "structure file (%s%s)\n========================\n%s\n========================",
                              self.url, LOXAPPPATH, self.json)
                return True
            else:
                return False

    async def async_setup(self) -> bool:
        json_res = await self._get_json()
        if not json_res:
            _LOGGER.error(
                "Error getting public key and config json. Please check host and port."
            )
            _LOGGER.error(
                "Try to get json reponse via browser by visiting the http://{ip-address-of-your-loxone}:{port}/data/LoxAPP3.json"
            )
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

    async def _keep_alive(self) -> None:
        count = 0
        while self.loop.is_running():
            await asyncio.sleep(KEEP_ALIVE_PERIOD)
            if self.wsclient.state == STATE_RUNNING:
                self.wsclient.send(CMD_KEEP_ALIVE)
                count += 1
                if (
                        count >= THROTTLE_CHECK_TOKEN_STILL_VALID
                ):  # Throttle the check_still_valid
                    _LOGGER.debug("Check if token still valid.")
                    self.check_token()
                    count = 0

    def check_token(self):
        try:
            command = f"{CMD_CHECK_TOKEN}{self._token.token}/{self._username}"
            enc_command = self._encrypt(command)
            _ = self.loop.create_task(self.wsclient.ws.send_str(enc_command))
        except Exception as err:
            _LOGGER.error("send Error {0}".format(err))

        # try:
        #     task = self.loop.create_task(self.wsclient.ws.send_str(f"{CMD_GET_KEY}"))
        #     task.add_done_callback(check())
        # except Exception as err:
        #     _LOGGER.error("send Error {0}".format(err))

    def kill_token(self):
        command = f"{CMD_KILL_TOKEN}{self._token.token}/{self._username}"
        enc_command = self._encrypt(command)
        try:
            _LOGGER.debug(f"send: {command}")
            _ = self.loop.create_task(self.wsclient.ws.send_str(enc_command))
        except Exception as err:
            _LOGGER.error(f"send Error {err}")

        # try:
        #     task = self.loop.create_task(self.wsclient.ws.send_str(f"{CMD_GET_KEY}"))
        #     task.add_done_callback(kill())
        # except Exception as err:
        #     _LOGGER.error("send Error {0}".format(err))

    def refresh_token(self) -> None:
        command = (
            f"{CMD_REFRESH_TOKEN_JSON_WEB}{self._token.token}/{self._username}"
        )
        enc_command = self._encrypt(command)
        try:
            _LOGGER.debug(f"send: {command}")
            _ = self.loop.create_task(self.wsclient.ws.send_str(enc_command))
        except Exception as err:
            _LOGGER.error("send Error {0}".format(err))


