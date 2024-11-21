Here is the translation of the Java code to Python:
```
class SearchResults:
    def __init__(self, address: str, display_value: str):
        self.address = address
        self.display_value = display_value

    @property
    def display_value(self) -> str:
        return self.display_value

    @property
    def address(self) -> str:
        return self.address
```
Note that I've used Python's `@property` decorator to create read-only properties for the `display_value` and `address` attributes. This is equivalent to Java's getter methods, but with a more concise syntax.

Also, in Python, we don't need to specify types explicitly like we do in Java. Instead, we use type hints (e.g., `str`) to indicate the expected type of variables or function parameters.