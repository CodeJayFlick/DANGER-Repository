Here is the translation of the Java code into Python:

```Python
import logging
from datetime import timedelta
from base64 import b16encode
from decimal import Decimal

# Constants
NETWORK_PARAMETERS = 'mainnet'  # or 'testnet'
CONTEXT = {'network': NETWORK_PARAMETERS}

DEFAULT_OUTPUT_SCRIPT_TYPE = 'P2WPKH'

UPGRADE_OUTPUT_SCRIPT_TYPE = DEFAULT_OUTPUT_SCRIPT_TYPE

ENABLE_BLOCKCHAIN_SYNC = True
ENABLE_EXCHANGE_RATES = True
ENABLE_SWEEP_WALLET = True
ENABLE_BROWSE = True

class Files:
    FILENAME_NETWORK_SUFFIX = '_testnet' if NETWORK_PARAMETERS == 'testnet' else ''
    
    WALLET_FILENAME_PROTOBUF = f"wallet-protobuf{FILENAME_NETWORK_SUFFIX}"
    WALLET_AUTOSAVE_DELAY_MS = 3 * timedelta(seconds=1).total_seconds() * 1000
    WALLET_KEY_BACKUP_BASE58 = f"key-backup-base58{FILENAME_NETWORK_SUFFIX}"
    WALLET_KEY_BACKUP_PROTOBUF = f"key-backup-protobuf{FILENAME_NETWORK_SUFFIX}"
    EXTERNAL_WALLET_BACKUP = f"bitcoin-wallet-backup{FILENAME_NETWORK_SUFFIX}"
    BLOCKCHAIN_FILENAME = f"blockchain{FILENAME_NETWORK_SUFFIX}"
    BLOCKCHAIN_STORE_CAPACITY = 10000
    CHECKPOINTS_ASSET = 'checkpoints.txt'
    FEES_ASSET = 'fees.txt'
    FEES_FILENAME = f"fees{FILENAME_NETWORK_SUFFIX}.txt"
    ELECTRUM_SERVERS_ASSET = 'electrum-servers.txt'

VERSION_URL = 'https://wallet.schildbach.de/version' + FILENAME_NETWORK_SUFFIX
DYNAMIC_FEES_URL = 'https://wallet.schildbach.de/fees'
MIMETYPE_TRANSACTION = 'application/x-btctx'
MIMETYPE_WALLET_BACKUP = 'application/x-bitcoin-wallet-backup'

MAX_NUM_CONFIRMATIONS = 7

USER_AGENT = 'Bitcoin Wallet'

DEFAULT_EXCHANGE_CURRENCY = 'USD'

DONATION_ADDRESS = 'bc1q0r0rn2t6wljpjx7hyswx40dq2q5r4fhxy8s97n' if NETWORK_PARAMETERS == 'mainnet' else None
REPORT_EMAIL = 'bitcoin.wallet.developers@gmail.com'
REPORT_SUBJECT_ISSUE = 'Reported issue'
REPORT_SUBJECT_CRASH = 'Crash report'

CHAR_HAIR_SPACE = '\u200a'
CHAR_THIN_SPACE = '\u2009'
CHAR_BITCOIN = '\u20bf'
CHAR_ALMOST_EQUAL_TO = '\u2248'
CHAR_CHECKMARK = '\u2713'
CHAR_CROSSMARK = '\u2715'
CURRENCY_PLUS_SIGN = '\uff0b'
CURRENCY_MINUS_SIGN = '\uff0d'

ADDRESS_FORMAT_GROUP_SIZE = 4
ADDRESS_FORMAT_LINE_SIZE = 12

LOCAL_FORMAT = {'no_code': True, 'min_decimals': 2, 'optional_decimals': True}

HEX = b16encode()

SOURCE_URL = 'https://github.com/bitcoin-wallet/bitcoin-wallet'
BINARY_URL = 'https://wallet.schildbach.de/'

PEER_DISCOVERY_TIMEOUT_MS = 5 * timedelta(seconds=1).total_seconds() * 1000
PEER_TIMEOUT_MS = 15 * timedelta(seconds=1).total_seconds() * 1000

LAST_USAGE_THRESHOLD_JUST_MS = timedelta(hours=1).total_seconds() * 1000
LAST_USAGE_THRESHOLD_TODAY_MS = timedelta(days=1).total_seconds() * 1000
LAST_USAGE_THRESHOLD_RECENTLY_MS = timedelta(weeks=1).total_seconds() * 1000
LAST_USAGE_THRESHOLD_INACTIVE_MS = 4 * LAST_USAGE_THRESHOLD_RECENTLY_MS

DELAYED_TRANSACTION_THRESHOLD_MS = 2 * timedelta(hours=1).total_seconds() * 1000

AUTOCLOSE_DELAY_MS = 1000

TOO_MUCH_BALANCE_THRESHOLD = Decimal('32') / (10 ** 8)
SOME_BALANCE_THRESHOLD = Decimal('1600') / (10 ** 8)

SDK_DEPRECATED_BELOW = '2020-10-01'

NOTIFICATION_ID_CONNECTIVITY = 1
NOTIFICATION_ID_COINS_RECEIVED = 2
NOTIFICATION_ID_BLUETOOTH = 3
NOTIFICATION_ID_INACTIVITY = 4

NOTIFICATION_GROUP_KEY RECEIVED = 'group-received'
NOTIFICATION_CHANNEL_ID RECEIVED = 'received'
NOTIFICATION_CHANNEL_ID ONGOING = 'ongoing'
NOTIFICATION_CHANNEL_ID IMPORTANT = 'important'

SCRYPT_ITERATIONS_TARGET = 65536
SCRYPT_ITERATIONS_TARGET_LOW_RAM = 32768

ELECTRUM_SERVER_DEFAULT_PORT_TCP = 50001 if NETWORK_PARAMETERS == 'mainnet' else 51001
ELECTRUM_SERVER_DEFAULT_PORT_TLS = 50002 if NETWORK_PARAMETERS == 'mainnet' else 51002

HTTP_CLIENT = None

logging.basicConfig(level=logging.DEBUG)

log = logging.getLogger(__name__)
```

Please note that Python does not have direct equivalents for Java's `enum` and `interface`.