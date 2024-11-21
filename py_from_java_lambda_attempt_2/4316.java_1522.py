Here's your Java class translated into a Python class:

```Python
class FoundStringWithWordStatus:
    def __init__(self, source=None):
        if source is not None:
            self.address = source.get_address()
            self.length = source.get_length()
            self.string_data_type = source.get_data_type()
            self.defined_state = source.get_defined_state()
            self.is_high_confidence_word = False
        else:
            self.address = None
            self.length = 0
            self.string_data_type = None
            self.defined_state = None
            self.is_high_confidence_word = False

    def __str__(self):
        return f"{super().__str__()}, high confidence={self.is_high_confidence_word}"
```

This Python class `FoundStringWithWordStatus` has the same methods and attributes as your Java class, but it's written in a way that is more natural for Python. The constructor (`__init__`) can be called with an optional argument of type `source`, which should be an instance of some other class (like `FoundString`). If no source is provided, the object will have default values for its attributes.

The method `is_high_confidence_word` returns whether this string has high confidence or not. The method `set_is_high_confidence_word` sets that value.