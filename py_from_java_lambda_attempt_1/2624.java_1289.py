Here is the translation of the Java code to Python:
```
class TraceSnap:
    def __init__(self):
        pass

    def get_trace(self) -> 'Trace':
        raise NotImplementedError("Subclasses must implement this method")

    def get_snap(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define an abstract base class (ABC) using the `class` statement with no implementation for its methods.

The `get_trace()` and `get_snap()` methods are declared as abstract because they raise a `NotImplementedError`, indicating that subclasses must provide their own implementations of these methods.