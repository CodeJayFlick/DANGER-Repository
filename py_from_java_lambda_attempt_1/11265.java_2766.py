Here is the translation of the Java code to Python:

```Python
class PluginException(Exception):
    def __init__(self, message, details=None):
        if details:
            super().__init__("Can't add plugin: " + str(message) + ". " + str(details))
        else:
            super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)

    @classmethod
    def from_message_and_cause(cls, message, cause):
        return cls(message, cause)

    def get_plugin_exception(self, e=None):
        if not e:
            return self
        return PluginException(f"{e.message}\n{self.message}")
```

Note that Python does not have a direct equivalent to Java's `UsrException` class. Instead, we can use the built-in `Exception` class and create our own custom exception classes as needed.