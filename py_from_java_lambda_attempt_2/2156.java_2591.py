Here is the translation of the Java code to Python:
```
class DebuggerModelTypeException(Exception):
    @classmethod
    def type_required(cls, got, path, expected_type):
        return cls(f"Path {path} does not refer to a {expected_type.__name__}. Got {got} (of {type(got).__name__})")

    @classmethod
    def link_forbidden(cls, target_object, path):
        return cls(f"Path {path} is a link to {target_object.path}, but following links was forbidden")

    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message, cause)
```
Note that I've used the built-in `Exception` class as a base for our custom exception class. This is equivalent to Java's `RuntimeException`. The rest of the code translates fairly directly from Java to Python.

Also note that in Python, we don't need to specify types explicitly like you do in Java with `Class<?> expected_type`. Instead, we can use the built-in `type()` function to get the type of an object.