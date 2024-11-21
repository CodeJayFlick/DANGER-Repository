Here is the translation of the Java code to Python:
```
class UnsupportedFillTypeException(Exception):
    def __init__(self, data_type: str) -> None:
        super().__init__(f"Unsupported linear fill data type: [{data_type}]")
        self.status_code = 400
```
Note that I've used a custom exception class `UnsupportedFillTypeException` and inherited from the built-in Python `Exception`. The constructor takes one argument, `data_type`, which is expected to be a string. In the `__init__` method, we call the parent's constructor with a formatted error message using f-strings (Python 3.6+), and set an attribute `status_code` to 400.

This Python code does not have direct equivalents for Java classes like `TSStatusCode`, `TSDataType`, or package-level imports from other packages. Instead, we rely on built-in Python types and exceptions.