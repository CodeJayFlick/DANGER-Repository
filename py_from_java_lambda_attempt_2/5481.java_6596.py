Here is the equivalent Python code:

```Python
class FieldStringInfo:
    def __init__(self, parent_string: str, field_string: str, offset: int):
        self.parent_string = parent_string
        self.field_string = field_string
        self.offset = offset

    @property
    def get_offset(self) -> int:
        return self.offset

    @property
    def get_parent_string(self) -> str:
        return self.parent_string

    @property
    def get_field_string(self) -> str:
        return self.field_string

    def __str__(self):
        return f"{type(self).__name__}[\nfieldString={self.field_string},\nparentString={self.parent_string}\n]"
```

Note that Python does not have direct equivalent of Java's `public` and `private`. In Python, everything is public by default. If you want to make a variable private in Python, you can use double underscore prefix (`__`) which makes the attribute name mangled (i.e., it becomes `_FieldStringInfo__parent_string`, etc.), but this is not exactly equivalent of Java's private variables.