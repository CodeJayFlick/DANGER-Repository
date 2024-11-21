Here is the translation of the Java code to Python:
```
class DWARFE Exception(Exception):
    """Constructs a DWARFException with the specified message."""
    def __init__(self, message: str) -> None:
        super().__init__(message)
```
Note that in Python, we don't need to specify `public` or `extends`, and we use indentation instead of curly braces for block-level structure. The constructor (`__init__`) is also defined differently than in Java.

Also, I've kept the docstring (the triple-quoted string) as it was in the original code, but Python's docstrings are typically written using triple quotes `"""..."""` or single quotes `'...'`.