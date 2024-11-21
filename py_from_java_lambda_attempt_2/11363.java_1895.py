Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message, cause)
```

Note that in Python, we don't need to specify the type of a class or method. Also, Python's `Exception` is equivalent to Java's `Exception`.