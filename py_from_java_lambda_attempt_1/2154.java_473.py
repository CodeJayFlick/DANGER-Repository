Here is the translation of the Java code to Python:
```
class DebuggerModelNoSuchPathException(Exception):
    def __init__(self, message, cause=None):
        super().__init__(message)
        self.cause = cause
```
Note that in Python, we don't need a separate `DebuggerRuntimeException` class since all exceptions are subclasses of the built-in `Exception` class. We also use the `super()` function to call the constructor of the parent class (`Exception`) and set the `cause` attribute if it's provided.

The second constructor is not necessary in Python, as we can simply pass a message string to the first constructor:
```
e = DebuggerModelNoSuchPathException("No such path")
```