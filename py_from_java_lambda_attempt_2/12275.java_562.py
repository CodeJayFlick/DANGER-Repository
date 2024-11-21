Here is the translation of the Java interface `DataTypeDisplayOptions` to a Python class:

```python
class DataTypeDisplayOptions:
    MAX_LABEL_STRING_LENGTH = 32

    DEFAULT = type("DEFAULT", (object,), {
        "use_abbreviated_form": lambda self: False,
        "get_label_string_length": lambda self: MAX_LABEL_STRING_LENGTH
    })

    def __init__(self):
        pass

    def use_abbreviated_form(self) -> bool:
        return False

    def get_label_string_length(self) -> int:
        return DataTypeDisplayOptions.MAX_LABEL_STRING_LENGTH


# Note that in Python, we don't need to define the methods as static
class DefaultDataTypeDisplayOptions(DataTypeDisplayOptions):
    pass
```

Note that I've used a lambda function to implement the `use_abbreviated_form` method for the default instance. This is equivalent to the Java interface's implementation of this method.

Also, in Python, we don't need to define methods as static, so I removed the `static` keyword from the original code.