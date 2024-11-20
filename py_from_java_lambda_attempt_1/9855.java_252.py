Here is the translation of the Java interface into a Python class:

```Python
class TableTextFilterFactory:
    def get_table_filter(self, text: str, transformer) -> 'TableFilter':
        pass  # This method needs implementation in your specific use case.
```

Note that this code does not include any actual filtering logic. It only defines the interface for a factory class to create table filters based on given text and row transformers.

Here's how you might implement it:

```Python
class TableTextFilterFactory:
    def get_table_filter(self, text: str, transformer) -> 'TableFilter':
        return TableRowFilter(text, transformer)

class TableRowFilter(TableFilter):
    def __init__(self, text: str, transformer):
        self.text = text
        self.transformer = transformer

    def filter(self, row_object) -> bool:
        # Implement your filtering logic here.
        transformed_row = [str(x) for x in self.transformer(row_object)]
        return any(text.lower() in str_value.lower() for str_value in transformed_row)
```

This implementation creates a `TableRowFilter` class that filters table rows based on the given text and row transformer. The filter function transforms the row object into a list of strings, then checks if the given text is present in any of those strings (case-insensitive).