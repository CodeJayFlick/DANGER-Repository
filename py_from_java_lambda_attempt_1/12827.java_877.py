Here is the translation of the Java code into Python:

```Python
class VariableTypeFieldLocation:
    def __init__(self, program=None, location_addr=None, var=None, char_offset=0):
        self.type_str = None
        if program and var:
            super().__init__(program, var, 0, char_offset)
            self.type_str = var.data_type.name

    @property
    def type(self):
        return self.type_str

    def __str__(self):
        return f"{super().__str__}, Function Variable Type = {self.type}"

    def __hash__(self):
        result = super().__hash__()
        if self.type_str:
            result += hash(self.type_str)
        return result

    def __eq__(self, other):
        if not isinstance(other, VariableTypeFieldLocation):
            return False
        if not super().__eq__(other):
            return False
        if self.type_str != other.type_str:
            return False
        return True

    def restore_state(self, program=None, obj={}):
        super().restore_state(program, obj)
        self.type_str = obj.get("_TYPE_STR", "")

    def save_state(self, obj={}):
        super().save_state(obj)
        obj["_TYPE_STR"] = self.type_str
```

Note that Python does not have direct equivalent of Java's `public` and `private` access modifiers. In this translation, I've omitted them as they are not necessary in Python.