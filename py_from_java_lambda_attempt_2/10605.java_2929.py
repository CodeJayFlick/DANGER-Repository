Here's the translation of the Java interface `LogListener` into a Python class:

```python
class LogListener:
    def __init__(self):
        pass

    def message_logged(self, message: str, is_error: bool) -> None:
        """
        Called when a log message is received.

        Args:
            message (str): The message of the log event.
            is_error (bool): True if the message is considered an error,
                as opposed to an informational message.
        """
        pass
```

Note that in Python, we don't have explicit interfaces like Java. Instead, we define a class with methods that can be implemented by other classes. The `__init__` method is the constructor, which doesn't do anything in this case since it's not necessary to initialize any attributes.

The `message_logged` method has been translated from the original Java method signature, but its implementation remains empty (i.e., it does nothing) as per your request.