from __future__ import annotations

import logging
import traceback

_LOGGER = logging.getLogger(__name__)


class MiniServer:
    """This class connects to the Loxone Miniserver."""

    def __init__(
        self,
        host=None,
        port=None,
        username=None,
        password=None,
        publickey=None,
        privatekey=None,
        key=None,
        iv=None,
    ):
        """Initialize Miniserver class."""
        self.host: str = host
        self.port: int = port
        self.username: str = username
        self.password: str = password
        self.message_header = None
        self.message_body = None
        self.api: LoxAPI | None = None

    async def async_setup(self) -> bool:
        self.api = LoxAPI(
            host=self.host, port=self.port, user=self.username, password=self.password
        )
        json_res = await self.api.get_json()
        if not json_res:
            _LOGGER.error("Error getting public key and config jsson.")
            return False

        res_init = await self.api.async_init()
        if not res_init:
            _LOGGER.error("Error initialisation.")
            return False
        return True





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
