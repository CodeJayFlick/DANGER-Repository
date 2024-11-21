Here is the translation of the Java code to Python:
```
class StatementExecutionException(Exception):
    def __init__(self, status=None, reason=None, cause=None):
        if status:
            message = f"{status.code}: {status.message}"
        elif reason:
            message = reason
        else:
            message = "Unknown error"
        super().__init__(message)
        self.status_code = status.code if status else None

    def get_status_code(self):
        return self.status_code
```
Note that I've used Python's built-in `Exception` class as the base class for our custom exception, and implemented the same constructor methods (`__init__`) to handle different types of initialization. The `get_status_code()` method is also similar to its Java counterpart.

Also, in Python, we don't need to specify explicit getters/setters like we do in Java; instead, we can access instance variables directly using dot notation (e.g., `self.status_code`).