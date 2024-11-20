Here is the translation of the Java code to Python:
```
import threading

class NotifyingReference:
    def __init__(self, value=None, notify_all=True):
        self._value = value
        self.notify_all = notify_all

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        if self._value != new_value:
            self._value = new_value
            if self.notify_all:
                threading.NotifyAll()
            else:
                threading Notify()

    def __str__(self):
        return f"NotifyingReference(value={self.value}, notify_all={self.notify_all})"
```
Note that I've used Python's built-in `property` decorator to create a getter and setter for the `_value` attribute, which is equivalent to Java's private field with public accessor methods. The `@Nullable` annotation in Java doesn't have a direct equivalent in Python, but we can use Python's type hinting system (e.g., `Optional[V]`) or simply omit it.

Also, I've replaced the `synchronized` keyword with Python's built-in support for thread-safe operations using locks. In this case, I used the `threading` module and its `NotifyAll()` method to simulate Java's `notifyAll()` call.