Here is the equivalent Python code:

```
class XmlException(Exception):
    def __init__(self):
        pass

    def __init__(self, message=""):
        super().__init__(message)

    def __init__(self, cause=None):
        if cause:
            super().__init__(str(cause))
        else:
            super().__init__()

    def __init__(self, message="", cause=None):
        if cause:
            super().__init__(f"{message}: {cause}")
        elif message:
            super().__init__(message)
        else:
            super().__init__()
```

Note that Python does not have a direct equivalent to Java's `extends` keyword. Instead, we define the class as a subclass of the built-in `Exception` class using inheritance.