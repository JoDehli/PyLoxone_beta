"""
Loxone constants

For more details about this component, please refer to the documentation at
https://github.com/JoDehli/pyloxone-api
"""
from __future__ import annotations

from typing import Final

# Loxone constants
TIMEOUT: Final = 60
KEEP_ALIVE_PERIOD: Final = 240
THROTTLE_CHECK_TOKEN_STILL_VALID: Final = (
    90  # 90 * KEEP_ALIVE_PERIOD -> 43200 sek -> 6 h
)

IV_BYTES: Final = 16
AES_KEY_SIZE: Final = 32

SALT_BYTES: Final = 16
SALT_MAX_AGE_SECONDS: Final = 60 * 60
SALT_MAX_USE_COUNT: Final = 30

TOKEN_PERMISSION: Final = 4  # 2=web, 4=app
TOKEN_REFRESH_RETRY_COUNT: Final = 5
# token will be refreshed 1 day before its expiration date
TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY: Final = (
    24 * 60 * 60
)  # 1 day --> Old. delete if new way is successful
MAX_REFRESH_DELAY: Final = 60 * 60 * 24  # 1 day


LOXAPPPATH: Final = "/data/LoxAPP3.json"

CMD_KEEP_ALIVE: Final = "keepalive"
CMD_GET_PUBLIC_KEY: Final = "jdev/sys/getPublicKey"
CMD_KEY_EXCHANGE: Final = "jdev/sys/keyexchange/"
CMD_GET_KEY_AND_SALT: Final = "jdev/sys/getkey2/"
CMD_REQUEST_TOKEN: Final = "jdev/sys/gettoken/"
CMD_REQUEST_TOKEN_JSON_WEB: Final = "jdev/sys/getjwt/"
CMD_GET_KEY: Final = "jdev/sys/getkey"
CMD_AUTH_WITH_TOKEN: Final = "authwithtoken/"
CMD_REFRESH_TOKEN: Final = "jdev/sys/refreshtoken/"
CMD_REFRESH_TOKEN_JSON_WEB: Final = "jdev/sys/refreshjwt/"
CMD_CHECK_TOKEN: Final = "jdev/sys/checktoken/"
CMD_KILL_TOKEN: Final = "jdev/sys/killtoken/"
CMD_ENCRYPT_CMD: Final = "jdev/sys/enc/"
CMD_ENABLE_UPDATES: Final = "jdev/sps/enablebinstatusupdate"
CMD_GET_VISUAL_PASSWD: Final = "jdev/sys/getvisusalt/"

DEFAULT_TOKEN_PERSIST_NAME: Final = "lox_token.cfg"
LOX_CONFIG: Final = "loxconfig"
