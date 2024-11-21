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
