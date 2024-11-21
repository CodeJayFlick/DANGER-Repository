Here is the translation of the Java code to Python:
```
class UndefinedTemplateException(Exception):
    def __init__(self, path: str) -> None:
        message = f"Undefined template name: {path}"
        super().__init__(message)
        self.status_code = TSStatusCode.UNDEFINED_TEMPLATE
        self.is_transient_error = True

TSStatusCode = int  # assuming this is an enum in Java, we can use a Python integer here
```
Note that I've used the built-in `Exception` class as the base class for our custom exception. In Python, exceptions are typically defined using classes that inherit from the built-in `Exception` or `BaseException` classes.

I've also replaced the `String.format()` method with an f-string (a new feature in Python 3.6+) to create the error message. The rest of the code is straightforward translations of Java code to equivalent Python syntax.