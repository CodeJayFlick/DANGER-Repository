Here is the translation of the Java interface `InterpreterConnection` to a Python class:

```python
class InterpreterConnection:
    def __init__(self):
        pass

    def get_title(self) -> str:
        """Gets the title of the interpreter."""
        return ""

    def get_icon(self) -> bytes:
        """Gets the icon associated with the interpreter. Null if default icon is desired."""
        return None  # or b"" for a null byte string

    def get_completions(self, cmd: str) -> list:
        """Gets a list of code completions for the given command."""
        return []
```

Note that I've used Python's type hints to indicate the expected types of the method parameters and return values. In particular:

* The `get_title` and `get_icon` methods have no parameters, so their parameter lists are empty.
* The `get_completions` method takes a single string parameter (`cmd`) and returns a list (specifically, an empty list).
* I've used the `-> str`, `-> bytes`, and `-> list` syntax to indicate that these methods return strings, byte objects, and lists, respectively.

In Python, we don't need explicit getters or setters like Java does. Instead, we can simply define instance variables (not shown here) and access them directly using dot notation (`self.variable_name`).