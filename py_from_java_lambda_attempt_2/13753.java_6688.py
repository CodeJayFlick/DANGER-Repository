Here is the translation of the given Java code into Python:

```Python
import logging
import time
from enum import Enum

class RemoteServiceStatus(Enum):
    FAILURE = 0


class ServiceAmbassador:
    RETRIES = 3
    DELAY_MS = 3000

    def __init__(self):
        pass

    def do_remote_function(self, value: int) -> long:
        return self.safe_call(value)

    def check_latency(self, value: int) -> (long, int):
        start_time = time.time()
        result = RemoteService().do_remote_function(value)
        time_taken = time.time() - start_time

        logging.info("Time taken (ms): {}".format(time_taken))
        return result, time_taken

    def safe_call(self, value: int) -> long:
        retries = 0
        result = RemoteServiceStatus.FAILURE.value

        for i in range(self.RETRIES):
            if retries >= self.RETRIES:
                return result

            if (result := self.check_latency(value)[0]) == RemoteServiceStatus.FAILURE.value:
                logging.info("Failed to reach remote: ({})".format(i + 1))
                retries += 1
                time.sleep(self.DELAY_MS / 1000)
            else:
                break

        return result


class RemoteService:
    def do_remote_function(self, value: int) -> long:
        # This method should be implemented according to your requirements.
        pass
```

Note that this translation assumes the existence of a `RemoteService` class with a `do_remote_function` method. The actual implementation of this method depends on how you want to interact with your remote service in Python.