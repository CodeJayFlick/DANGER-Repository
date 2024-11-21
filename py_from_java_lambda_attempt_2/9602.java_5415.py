Here is the translation of the Java interface `HighlightFactory` to a Python class:

```python
class HighlightFactory:
    def get_highlights(self, field: 'Field', text: str, cursor_text_offset: int) -> list:
        """
        Returns the highlights for the given text.

        Args:
            field (Field): The field that is requesting the highlight.
            text (str): The text to be considered for highlighting.
            cursor_text_offset (int): The position in the given text of the cursor. A -1 indicates
                the cursor is not in this field.

        Returns:
            list: An array of highlights to be rendered.
        """
        pass  # Implement me!
```

Note that I've used type hints for the method parameters and return value, but Python itself does not enforce these types at runtime. The `pass` statement indicates where you would implement the logic for this method in a real-world scenario.

Also, since there is no equivalent to Java's `interface` keyword in Python, we use a class with only abstract methods (i.e., methods that are declared but have no implementation) to achieve similar functionality.