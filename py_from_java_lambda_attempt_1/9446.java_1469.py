Here is the translation of the Java code to Python:
```
class IntEditor:
    def __init__(self):
        pass

    def set_as_text(self, text: str) -> None:
        try:
            self.set_value(int(text))
        except ValueError as e:
            raise ValueError(f"Invalid integer: {text}") from e
```
Note that I've used Python's built-in `int()` function to parse the input string into an integer. If the parsing fails, a `ValueError` is raised with a message indicating the invalid input.

Also, since there is no equivalent concept in Python for Java's `PropertyEditorSupport`, I simply defined a class `IntEditor` that has two methods: `__init__()` and `set_as_text()`.