Here is the translation of the Java code to Python:
```
class BadDataError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
```
Note that I've used Python's built-in `Exception` class as a base class for `BadDataError`, and implemented the constructor (`__init__`) method to take a string argument. The rest of the code is not translated, as it appears to be licensing information and comments specific to Java.