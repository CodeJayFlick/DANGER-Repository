Here is the translation of the given Java code into Python:

```Python
class ConflictInfo:
    def __init__(self, list_name: str, property_name: str, latest_type: int, my_type: int,
                 orig_type: int, latest_value=None, my_value=None, orig_value=None):
        self.list_name = list_name
        self.property_name = property_name

        if Options.DELIMITER in property_name:
            pos = property_name.rfind(Options.DELIMITER)
            if pos > 0:
                self.group_name = f"{list_name} {property_name[:pos]}"
                self.displayed_property_name = property_name[pos + len(Options.DELIMITER):]
            else:
                self.group_name = list_name
                self.displayed_property_name = property_name

        self.my_type = my_type
        self.latest_type = latest_type
        self.orig_type = orig_type
        self.my_value = my_value
        self.latest_value = latest_value
        self.orig_value = orig_value

    def is_type_match(self) -> bool:
        return self.my_type == self.latest_type

    @property
    def list_name(self):
        return self.list_name

    @property
    def property_name(self):
        return self.property_name

    @property
    def displayed_property_name(self):
        return self.displayed_property_name

    @property
    def group_name(self):
        return self.group_name

    @property
    def latest_type_string(self) -> str:
        if self.latest_type == 0:  # BOOLEAN_ TYPE
            return "boolean"
        elif self.latest_type == 1:  # DOUBLE_TYPE
            return "double"
        elif self.latest_type == 2:  # INT_TYPE
            return "integer"
        elif self.latest_type == 3:  # LONG_TYPE
            return "long"
        elif self.latest_type == 4:  # STRING_ TYPE
            return "string"
        elif self.latest_type == 5:  # DATE_ TYPE
            return "date"
        else:
            return "unknown"

    @property
    def my_type_string(self) -> str:
        if self.my_type == 0:  # BOOLEAN_ TYPE
            return "boolean"
        elif self.my_type == 1:  # DOUBLE_TYPE
            return "double"
        elif self.my_type == 2:  # INT_TYPE
            return "integer"
        elif self.my_type == 3:  # LONG_TYPE
            return "long"
        elif self.my_type == 4:  # STRING_ TYPE
            return "string"
        elif self.my_type == 5:  # DATE_ TYPE
            return "date"
        else:
            return "unknown"

    @property
    def orig_type_string(self) -> str:
        if self.orig_type == 0:  # BOOLEAN_ TYPE
            return "boolean"
        elif self.orig_type == 1:  # DOUBLE_TYPE
            return "double"
        elif self(orig_type == 2):  # INT_TYPE
            return "integer"
        elif self.orig_type == 3:  # LONG_TYPE
            return "long"
        elif self.orig_type == 4:  # STRING_ TYPE
            return "string"
        elif self.orig_type == 5:  # DATE_ TYPE
            return "date"
        else:
            return "unknown"

    @property
    def latest_value(self):
        return self.latest_value

    @property
    def my_value(self):
        return self.my_value

    @property
    def orig_value(self):
        return self.orig_value

    @property
    def latest_type(self):
        return self.latest_type

    @property
    def my_type(self):
        return self.my_type

    @property
    def orig_type(self):
        return self.orig_type


class Options:
    DELIMITER = "-"
```

Please note that I have not included the `OptionType` class as it seems to be specific to your Java code and does not translate directly into Python.