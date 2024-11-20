Here is the translation of the given Java code into equivalent Python:

```Python
class PdbException(Exception):
    def __init__(self, message):
        super().__init__(message)
```

This Python class `PdbException` inherits from built-in exception class `Exception`. The constructor (`__init__`) takes a string argument and uses the parent's constructor to set this as its own error message.