class SendCoinsViewModel:
    class State(enum):
        REQUEST_PAYMENT_REQUEST = 1
        INPUT = 2
        DECRYPTING = 3
        SIGNING = 4
        SENDING = 5
        SENT = 6
        FAILED = 7

    def __init__(self, application: WalletApplication):
        self.application = application
        self.address_book = AddressBookDatabase.get_database(application).get_all()
        self.exchange_rate = SelectedExchangeRateLiveData(self.application)
        self.dynamic_fees = DynamicFeeLiveData(self.application)
        self.balance = WalletBalanceLiveData(self.application, BalanceType.AVAILABLE)
        self.sent_transaction = TransactionLiveData(self.application)

    state: Optional[State] = None
    payment_intent: Optional[PaymentIntent] = None
    fee_category: FeeCategory = FeeCategory.NORMAL
    validated_address: Optional[AddressAndLabel] = None
    direct_payment_ack: Optional[Boolean] = None
    dryrun_transaction: Optional[Transaction] = None
    dryrun_exception: Optional[Exception] = None

class AddressBookEntry:
    pass

class SelectedExchangeRateLiveData:
    def __init__(self, application):
        self.application = application

class DynamicFeeLiveData:
    def __init__(self, application):
        self.application = application

class WalletBalanceLiveData:
    def __init__(self, application: WalletApplication, balance_type: BalanceType):
        self.application = application
        self.balance_type = balance_type

class TransactionLiveData:
    def __init__(self, application):
        self.application = application

class FeeCategory(enum):
    NORMAL = 1
