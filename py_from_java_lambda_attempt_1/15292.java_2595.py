Here is the translation of the given Java code into Python:

```Python
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
```

Please note that this translation does not include all classes and methods from the original Java code as some of them are missing or incomplete (like `DialogEvent`, `PrefixedChecksummedBytes` etc.).