Here is the translation of the Java code to Python:
```
class GadpException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message, cause)
```
Note that in Python, we don't need a `public` keyword for classes or methods. Also, the constructor (`__init__`) is used to initialize objects, and it's called when an object is created using the `()` operator.

In this translation, I've kept the same class name and method names as the original Java code, but Python uses double underscores (``) instead of single quotes for private variables.