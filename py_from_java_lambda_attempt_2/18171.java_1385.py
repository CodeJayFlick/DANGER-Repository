Here is the translation of the Java code to Python:
```
class TsFileRuntimeError(Exception):
    def __init__(self):
        pass

    def __init__(self, message: str = None, cause=None) -> None:
        if message:
            super().__init__(message)
        elif cause:
            super().__init__(cause)

    serialVersionUID = 6455048223316780984
```
Note that in Python, we don't need to specify the `public` access modifier or use a package declaration. Also, the `serialVersionUID` is not used in Python (it's specific to Java serialization).

The constructor (`__init__`) methods are similar to their Java counterparts: one takes no arguments, another takes a message and an optional cause, and another just takes a cause.

In Python, we use the built-in `Exception` class as the base class for our custom exception.