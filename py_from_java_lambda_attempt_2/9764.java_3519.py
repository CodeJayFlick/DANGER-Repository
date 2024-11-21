Here is the translation of the given Java code into Python:

```Python
class RangeColumnConstraint:
    def __init__(self, name: str, min_value: object, max_value: object, editor_provider: 'EditorProvider', group: str):
        self.name = name
        self.min_value = min_value
        self.max_value = max_value
        self.editor_provider = editor_provider
        self.group = group

    def get_group(self) -> str:
        return self.group

    def get_name(self) -> str:
        return self.name

    def get_min_value(self):
        return self.min_value

    def get_max_value(self):
        return self.max_value

    def get_column_type(self):
        return type(self.get_min_value())

    def get_editor(self, column_data_source: 'ColumnData'):
        return self.editor_provider.get_editor(self, column_data_source)

    def get_constraint_value_string(self) -> str:
        buf = f"[{self.editor_provider.to_string(self.min_value)}, {self.editor_provider.to_string(self.max_value)}]"
        return buf

    @staticmethod
    def parse_constraint_value(new_value: str, data_source: object):
        pattern = r"\[(\S+),(\S+)\]"

        if match := re.match(pattern, new_value):
            min_str, max_str = match.groups()
            new_min_value = self.editor_provider.parse_value(min_str.strip(), data_source)
            new_max_value = self.editor_provider.parse_value(max_str.strip(), data_source)

            return copy(new_min_value, new_max_value)

        raise ValueError(f"Don't know how to parse '{new_value}'")

    def __copy__(self, min: object, max: object):
        pass

class EditorProvider:
    @staticmethod
    def get_editor(constraint: 'RangeColumnConstraint', column_data_source: 'ColumnData'):
        # implementation here

    @staticmethod
    def to_string(value: object) -> str:
        # implementation here

    @staticmethod
    def parse_value(new_value: str, data_source: object):
        # implementation here

class ColumnData:
    pass

def copy(min: object, max: object):
    return RangeColumnConstraint("copy", min, max, EditorProvider(), "group")
```

Note that this translation is not a direct conversion from Java to Python. It's more of an interpretation of the given code in terms of Python syntax and semantics.

Also note that some parts of the original code are missing or incomplete (like `EditorProvider`, `ColumnData` classes, their methods), so you would need to implement them according to your needs.