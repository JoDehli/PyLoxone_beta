"""Represent the client session."""

import logging
import re

import aiohttp

_LOGGER = logging.getLogger(__name__)

STATE_STARTING = "starting"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
CONNECTING = "connecting"

RETRY_TIMER = 20
RETRY_COUTNER = 5

_PROTOCOL_STRIP = re.compile("^[^:]+://", re.IGNORECASE)


# _HTTPS_IDENTIFY = re.compile("^https://", re.IGNORECASE)


class WSClient:
    """This class client."""

    def __init__(
            self,
            loop,
            url: str,
            username: str,
            password: str,
            async_session_callback,
            async_message_callback,
    ):
        """init"""
        _LOGGER.debug("__init__")
        self.loop = loop
        self.session = None
        self.ws = None
        # TODO THIS DOES NOT WORK FOR WSS (IT MAY NOT KNOW CERTIFICATE -> solve this somehow)
        # tls = _HTTPS_IDENTIFY.match(url) is not None
        #  ("wss" if tls else "ws")
        self.url = "ws://" + _PROTOCOL_STRIP.sub("", url) + "/ws/rfc6455"
        self.username = username
        self.password = password
        self._state = None
        self._reconnect_counter = 0

        self.async_session_handler_callback = async_session_callback
        self.async_message_handler_callback = async_message_callback

        _LOGGER.debug("  self.url: %s", self.url)

    @property
    def state(self):
        # _LOGGER.debug("state")
        """state"""
        return self._state

    @state.setter
    def state(self, value):
        """state"""
        # _LOGGER.debug("state.setter")
        self._state = value
        _LOGGER.debug("Set Websocket state: {0}".format(value))
        self.async_session_handler_callback(self._state)

    def start(self):
        _LOGGER.debug("start")
        if self.state != STATE_RUNNING:
            self.state = STATE_STARTING
            return self.loop.create_task(self.running())
        return None

    async def running(self):
        """Start websocket connection."""
        _LOGGER.debug("running")

        try:
            self.session = aiohttp.ClientSession()
            self.ws = await self.session.ws_connect(self.url, protocols=("remotecontrol"))
            self.state = STATE_RUNNING
            self._reconnect_counter = 0

            async for msg in self.ws:
                if self.state == STATE_STOPPED:
                    break
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await self.async_message_handler_callback(msg.data, True)
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    await self.async_message_handler_callback(msg.data, False)
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    _LOGGER.debug("CLOSED")
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    _LOGGER.debug("ERROR")
                    break

        except aiohttp.ClientConnectorError:
            _LOGGER.debug("ClientConnectorError")
            if self.state != STATE_STOPPED:
                self.state = CONNECTING
                self.retry()
        except Exception as err:
            _LOGGER.error("Error {0}".format(err))
            if self.state != STATE_STOPPED:
                self.state = CONNECTING
                self.retry()
        else:
            _LOGGER.debug("other websocket issue")
            if self.state != STATE_STOPPED:
                self.state = CONNECTING
                self.retry()

        _LOGGER.debug("Finished running")

    def retry(self):
        """Retry to connect."""
        self._reconnect_counter += 1
        if self._reconnect_counter >= RETRY_COUTNER:
            self.loop.call_later(RETRY_TIMER, self.start)
            _LOGGER.debug("Reconnecting in %i.", RETRY_TIMER)

    def send(self, message):
        """send"""
        _LOGGER.debug("sending: {0}".format(message))
        if self.state == STATE_RUNNING:
            try:
                self.loop.create_task(self.ws.send_str(message))
            except Exception as err:
                _LOGGER.error("send Error {0}".format(err))

    async def stop(self):
        """Close websocket connection."""
        _LOGGER.debug("stop")
        self.state = STATE_STOPPED
        if not self.ws.closed:
            await self.ws.close()
            await self.session.close()
