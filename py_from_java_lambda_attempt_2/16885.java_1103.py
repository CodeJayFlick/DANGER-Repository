Here is the translation of the Java code to Python:
```
class IoTDATABASError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
```
Note that in Python, we don't need a `serialVersionUID` like in Java. Also, since Python doesn't have an equivalent of Java's `SQLException`, I used the built-in `Exception` class as the base class for our custom exception.

The constructor (`__init__`) takes a single argument `reason`, which is passed to the parent class using the `super().__init__(reason)` call.