Here is the translation of the Java code to Python:
```
class Error:
    def __init__(self, error_message):
        self.message = error_message

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, value):
        self._message = value
```
Note that I've used Python's `@property` decorator to create a read-only property for the `message` attribute. This is equivalent to Java's getter method.

Also, in Python, we don't need an explicit setter method like Java does with its `setMessage()` method. The `@property` decorator takes care of setting and getting the value automatically.