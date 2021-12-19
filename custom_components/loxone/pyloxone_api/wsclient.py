"""Represent the client session."""

import asyncio
import logging
import datetime
import aiohttp
import binascii

_LOGGER = logging.getLogger(__name__)

STATE_STARTING = "starting"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"
CONNECTING = "connecting"

RETRY_TIMER = 20


class WSClient:
    """This class client."""

    def __init__(
        self,
        loop,
        host,
        port,
        username,
        password,
        use_tls,
        async_session_callback,
        async_message_callback,
    ):
        """init"""
        _LOGGER.debug("__init__")
        self.loop = loop
        self.session = None
        self.ws = None
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._state = None
        self._use_tls = use_tls

        self.async_session_handler_callback = async_session_callback
        self.async_message_handler_callback = async_message_callback

        _LOGGER.debug("  self.host: {0}".format(self.host))
        _LOGGER.debug("  self.port: {0}".format(self.port))

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
            self.loop.create_task(self.running())


    async def running(self):
        """Start websocket connection."""
        _LOGGER.debug("running")

        scheme = "wss" if self._use_tls else "ws"
        url = f"{scheme}://{self.host}:{self.port}/ws/rfc6455"
        _LOGGER.debug("  url: {0}".format(url))

        try:
            self.session = aiohttp.ClientSession()
            self.ws = await self.session.ws_connect(url, protocols=("remotecontrol"))
            self.state = STATE_RUNNING

            async for msg in self.ws:
                if self.state == STATE_STOPPED:
                    break
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    _LOGGER.debug(
                        "Websocket BINARY data: {0}".format(binascii.hexlify(msg.data))
                    )
                    self.async_message_handler_callback(msg.data, True)
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    _LOGGER.debug("Websocket TEXT data: {0}".format(msg.data))
                    self.async_message_handler_callback(msg.data, False)
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

    def stop(self):
        """Close websocket connection."""
        _LOGGER.debug("stop")
        self.state = STATE_STOPPED
