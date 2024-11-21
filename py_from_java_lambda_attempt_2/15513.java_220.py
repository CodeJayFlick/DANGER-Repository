Here's your Java exception class translated into a Python equivalent:

```Python
class ModelException(Exception):
    def __init__(self, message=""):
        if not isinstance(message, str):
            raise TypeError("Message must be a string")
        super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)

    @classmethod
    def from_exception(cls, exception):
        return cls(str(exception))
```

This Python code defines a `ModelException` class that inherits from the built-in `Exception`. It has three constructors:

- The first constructor takes an optional string argument and sets it as the message for this exception.
- The second constructor creates an instance of `ModelException` with the given message. If no message is provided, it defaults to an empty string.
- The third constructor creates a new `ModelException` from another exception by converting that exception's message into a string.

The class also includes two class methods: `from_message`, which returns a new `ModelException` instance with the specified message; and `from_exception`, which converts another exception into a `ModelException`.