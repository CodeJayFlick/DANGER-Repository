Here is the translation of the Java interface `FilterTypeConverter` to a Python class:

```python
class FilterTypeConverter:
    def __init__(self):
        pass

    @property
    def filter_type(self) -> type:
        """Returns the destination class of the conversion"""
        raise NotImplementedError("Subclasses must implement this method")

    def convert(self, column_type: object, settings: dict = None) -> object:
        """Converts an instance of the column type to an instance of the destination type"""
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've used Python's built-in `object` type as a placeholder for the generic types `<COLUMN_TYPE>` and `<FILTER_TYPE>`, since Python does not support explicit type parameters like Java. The `filter_type` property is implemented using Python's `@property` decorator, which allows you to implement getter-only properties.

The `convert` method takes two arguments: `column_type` (an instance of the column type) and `settings` (a dictionary containing any settings needed for conversion). It returns an object of the destination type.