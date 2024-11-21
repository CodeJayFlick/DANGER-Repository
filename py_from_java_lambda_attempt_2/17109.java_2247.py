Here is the translation of the Java code to Python:
```
class QueryIdNotExsitException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.status_code = TSStatusCode.QUERY_ID_NOT_EXIST
```
Note that I've used the built-in `Exception` class in Python as a base class for our custom exception, and also used type hints for the method parameters.

Also, since there is no direct equivalent to Java's `TSStatusCode` enum in Python, we can simply use an integer constant or define it as a separate class if needed.