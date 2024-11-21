Here is the translation of the Java code into Python:

```Python
class FieldNameFieldLocation:
    def __init__(self, program=None, addr=None, component_path=None, field_name=None, char_offset=0):
        super().__init__(program, addr, component_path, 0, 0, char_offset)
        self.field_name = field_name

    def get_field_name(self):
        return self.field_name


class CodeUnitLocation:
    pass
```

Note that I've created a `CodeUnitLocation` class in Python as well, since the original Java code had this class defined. However, it's not clear what methods or attributes should be included in this class based on the provided Java code.

Also note that Python does not have direct equivalents to some of the Java concepts used here (e.g., `int[]`, `String`), so I've omitted those details for simplicity.