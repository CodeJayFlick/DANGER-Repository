Here is the translation of the Java code to Python:
```
class FormatArgument:
    def __init__(self, length_modifier: str, conversion_specifier: str):
        self.length_modifier = length_modifier
        self.conversion_specifier = conversion_specifier

    @property
    def length_modifier(self) -> str:
        return self.length_modifier

    @property
    def conversion_specifier(self) -> str:
        return self.conversion_specifier

    def __str__(self):
        return f"[{self.length_modifier}, {self.conversion_specifier}]"
```
Note that I used the `@property` decorator to create getter methods for the instance variables, which is a common pattern in Python. The `__init__` method initializes the object with the given length modifier and conversion specifier. The `__str__` method returns a string representation of the object using f-strings.

Also, I removed the Java-style comments (/* */) as they are not necessary in Python.