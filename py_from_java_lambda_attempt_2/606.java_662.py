Here is the translation of the given Java code into Python:

```Python
class DbgCommandError(Exception):
    def __init__(self, message=None, cmd=None, info=None):
        if message:
            super().__init__(message)
        elif cmd and info:
            super().__init__(f"{cmd} caused '{info}'")
        else:
            raise ValueError("Either a message or command and information must be provided")

    def get_info(self):
        return self.info
```

Note that Python does not have an exact equivalent to Java's `RuntimeException`. Instead, we can use the built-in `Exception` class as the base for our custom exception. The constructor of this class takes three parameters: a message (which is optional), and two objects (`cmd` and `info`) which are also optional.

The rest of the code translates directly from Java to Python.