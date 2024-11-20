Here is the translation of the Java code to Python:
```
class UnsupportedFilterDataTypeException(Exception):
    def __init__(self, message=None, cause=None):
        if cause is None:
            super().__init__(message)
        else:
            super().__init__(message, cause)

# Example usage
try:
    # some operation that raises an exception
    raise UnsupportedFilterDataTypeException("Invalid filter data type")
except UnsupportedFilterDataTypeException as e:
    print(f"Caught exception: {e}")
```
Note that in Python, we don't need to specify the `public` access modifier or use a package declaration like Java. Also, Python's `Exception` class is used instead of `RuntimeException`. The constructor (`__init__`) takes an optional `message` and/or `cause` parameter, which are passed to the parent `Exception` class using the `super()` function.