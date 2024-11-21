Here is a translation of the Java code into equivalent Python code:

```Python
import threading
from android.runnable import Runable
from android.content import Intent
from android.service import ServiceConnection
from android.os import IBinder
from androidx.lifecycle import LiveData
from de.schildbach.wallet.service import BlockchainService


class BlockchainServiceLiveData(LiveData):
    def __init__(self, context):
        self.context = context

    def on_active(self):
        intent = Intent(BlockchainService)
        self.context.bind_service(intent, self)

    def on_inactive(self):
        self.context.unbind_service(self)

    def on_service_connected(self, name, service):
        binder = IBinder(service)
        value = BlockchainService.LocalBinder(binder).get_service()
        self.set_value(value)

    def on_service_disconnected(self, name):
        self.set_value(None)


# Usage
class MyActivity:
    def __init__(self, context):
        self.context = context

    def start_activity(self):
        blockchain_service_live_data = BlockchainServiceLiveData(self.context)
        # Use the LiveData instance here


if __name__ == "__main__":
    pass  # This is not a main function in Python
```

Please note that this translation may not be perfect, as Java and Python are different languages with their own strengths.