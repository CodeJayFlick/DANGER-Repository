Here is the translation of the Java code to Python:
```
class FolderNotEmptyException(Exception):
    """Raised when an attempt is made to remove a folder which is not empty."""
    
    def __init__(self, msg: str) -> None:
        super().__init__(msg)
```
Note that in Python, we don't need to specify the `public` access modifier or use semicolons at the end of lines. We also use indentation to denote block-level structure instead of curly braces.

The `FolderNotEmptyException` class inherits from the built-in `Exception` class and overrides its constructor (`__init__`) method. The `super().__init__(msg)` call passes the error message `msg` to the parent class's constructor, which sets the exception's message attribute.