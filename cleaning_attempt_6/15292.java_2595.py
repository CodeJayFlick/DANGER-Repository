class SweepWalletViewModel:
    class State:
        DECODE_KEY = "decode_key"
        CONFIRM_SWEEP = "confirm_sweep"
        PREPARATION = "preparation"
        SENDING = "sending"
        SENT = "sent"
        FAILED = "failed"

    def __init__(self, application):
        self.application = application
        self.sent_transaction = TransactionLiveData(application)
        self.state = SweepWalletViewModel.State.DECODE_KEY

class DynamicFeeLiveData:
    pass  # This class is not implemented in the given Java code. It seems to be a LiveData object that holds dynamic fees.

class TransactionLiveData:
    def __init__(self, application):
        self.application = application
