Here is the translation of the Java code to Python:
```
class NoTemplateOnMNodeException(Exception):
    def __init__(self, path: str) -> None:
        message = f"NO template on {path}"
        super().__init__(message)
        self.status_code = 400
        self.is_transient_error = True

if __name__ == "__main__":
    try:
        raise NoTemplateOnMNodeException("some/path")
    except NoTemplateOnMNodeException as e:
        print(f"Error: {e}")
```
Note that I've used Python's built-in `Exception` class to create a custom exception, and the `super().__init__(message)` call is equivalent to calling the parent constructor in Java. The `status_code` attribute is not explicitly defined in the original code, but it seems reasonable to assume it would be an integer value (in this case, 400).