Here is the translation of the Java interface `ServerConfig` into a Python class:

```python
class ServerConfig:
    def __init__(self):
        pass

    @property
    def default_branch(self) -> str:
        """Gets the branch to use if not provided by the user."""
        return ""

    @property
    def send_stacktrace_to_client(self) -> bool:
        """Returns True if server stack trace should be sent to the client in case of error."""
        return False
```

Note that I've used Python's property decorator (`@property`) to create getter methods for the two attributes, as there is no direct equivalent to Java interfaces or getters/setters in Python.