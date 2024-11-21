Here is the translation of the Java code to Python:
```
class FileInUseException(Exception):
    """Indicates that there was contention for a file which is in-use.
       This can be caused for various reasons including a file lock of some kind."""
    
    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    def __init__(self, msg: str, cause: Exception) -> None:
        super().__init__(msg, cause)
```
Note that in Python, we don't need to specify the `public` access modifier since everything is public by default. Also, the `@param` comments are not necessary as they serve a similar purpose to docstrings.

The rest of the code remains largely unchanged, with the exception of using Python's built-in `Exception` class instead of extending `IOException`.