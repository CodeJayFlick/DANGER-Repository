Here is the translation of the given Java code into equivalent Python:

```Python
class GadpMessageException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message)
        self.__cause = cause
```

In this translation, we have created a `GadpMessageException` class that inherits from Python's built-in `Exception`. The constructor (`__init__`) of the exception takes two parameters: `message`, which is used to set the error message for the exception; and `cause`, which represents the underlying cause of the exception.