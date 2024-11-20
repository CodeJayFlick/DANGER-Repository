Here is the translation of the Java code to Python:
```
class GadpRuntimeException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message, cause)
```
Note that in Python, we don't need a `public` keyword for classes or methods. Also, the equivalent of Java's `extends RuntimeException` is simply inheriting from the built-in `Exception` class in Python.

The constructor (`__init__`) method takes two arguments: `self` (the instance itself) and `message`. The first argument is always passed implicitly when an object is created.