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
Note that I've used Python's `@property` decorator to create a read-only property for the `message` attribute. This is equivalent to Java's getter method. Similarly, the setter method is implemented using the `@setter` decorator.

Also, in Python, we don't need to explicitly define getters and setters like we do in Java. The above code achieves the same functionality as the original Java code without requiring explicit getter and setter methods.