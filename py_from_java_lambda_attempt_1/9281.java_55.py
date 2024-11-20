Here is the translation of the given Java code into Python:

```Python
class AbstractErrDialog:
    MAX_EXCEPTIONS = 100
    ERRORS_PREFIX = " ("
    ERRORS_SUFFIX = ") Errors"

    def __init__(self, title):
        pass  # equivalent to super().__init__()

    def dialog_closed(self):
        print("Closed callback called")

    def get_message(self):
        raise NotImplementedError

    def add_exception(self, message: str, t: Exception) -> None:
        raise NotImplementedError

    def get_exception_count(self) -> int:
        raise NotImplementedError

    def get_base_title(self) -> str:
        raise NotImplementedError

    def update_title(self):
        pass  # equivalent to self.title = ...

    def set_closed_callback(self, callback=None):
        if callback is not None:
            print("Setting closed callback")
```

Please note that Python does not have direct equivalents for Java's `abstract` classes and methods. Instead, we use the concept of abstract base classes (ABCs) from the `abc` module to define interfaces or abstract classes.

In this translation:

- The `Callback` class is replaced with a simple callback function.
- The `DialogComponentProvider` parent class is not translated as it seems to be specific to Java and does not have an equivalent in Python.