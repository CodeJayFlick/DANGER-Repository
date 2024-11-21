Here is the translation of the Java code to Python:
```
class DuplicatedTemplateException(Exception):
    def __init__(self, path: str) -> None:
        message = f"Failed to create duplicated template for path {path}"
        super().__init__(message)
        self.status_code = TSStatusCode.DUPLICATED_TEMPLATE
        self.is_client_error = True

TSStatusCode = int  # assuming this is an enum in the original code, we can just use a Python integer


# example usage:
try:
    raise DuplicatedTemplateException("path/to/template")
except Exception as e:
    print(f"Error: {e}")
```
Note that I've used Python's built-in `Exception` class to create our own custom exception type. The constructor (`__init__`) takes a single argument, the path string, and uses it to construct an error message. We also set two additional attributes on the exception instance: `status_code`, which is equivalent to the Java enum value, and `is_client_error`, which indicates whether this is a client-side or server-side error.

In Python, we don't need explicit getters and setters for these attributes; you can access them directly using dot notation (e.g., `exception_instance.status_code`).