Here is a translation of the Java code into equivalent Python:

```Python
import datetime
from threading import Thread
import time

class TimeLiveData:
    def __init__(self):
        self.value = None

    def start(self):
        thread = Thread(target=self.update_value)
        thread.daemon = True  # so that it stops when the main program ends
        thread.start()

    def update_value(self):
        while True:
            time.sleep(1)  # wait for one second before updating value again
            self.value = datetime.datetime.now()  # get current date and time

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        if self._value != new_value:
            self._value = new_value
            print(f"Value updated: {new_value}")  # you can replace this with whatever logic you want to execute when the value changes


# usage example:

live_data = TimeLiveData()
live_data.start()

while True:
    time.sleep(1)  # wait for one second before printing again
    if live_data.value is not None:
        print(f"Current date and time: {live_data.value}")
```

Please note that Python does not have a direct equivalent to Java's LiveData class. The above code uses a simple threading approach to simulate the behavior of updating the value periodically.

Also, this translation assumes that you want to update the value every second (as in your original Java code). If you need more complex logic or different timing for updates, please let me know and I'll be happy to help!