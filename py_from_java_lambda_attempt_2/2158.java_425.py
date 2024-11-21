Here is the translation of the Java code to Python:
```
class DebuggerRuntimeException(Exception):
    def __init__(self, message: str, cause=None) -> None:
        super().__init__(message)
        self.cause = cause
```
Note that in Python:

* We don't need a `package` declaration or an explicit `public` access modifier.
* The class inherits from the built-in `Exception` class instead of creating our own custom exception hierarchy.
* The constructor (`__init__`) takes two arguments: `message`, which is passed to the parent class's constructor, and `cause`, which can be set as a property on the instance.