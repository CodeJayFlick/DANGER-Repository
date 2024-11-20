Here is the translation of the Java code into Python:

```Python
class VariableNameFieldLocation:
    def __init__(self, program=None, location_addr=None, var=None, char_offset=0):
        self.name = None
        if var is not None:
            self.name = var.get_name()
        super().__init__(program, location_addr, var, 0, char_offset)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def __eq__(self, other):
        if not isinstance(other, VariableNameFieldLocation):
            return False
        if not super().__eq__(other):
            return False
        if self.name != other.name:
            return False
        return True

    def __hash__(self):
        result = super().__hash__()
        if self.name is None:
            result += 0
        else:
            result += hash(self.name)
        return result

    def restore_state(self, program, obj):
        super().restore_state(program, obj)
        self.name = obj.get("_VAR_NAME", None)

    def save_state(self, obj):
        super().save_state(obj)
        obj.put("_VAR_NAME", self.name)
```

Note that Python does not have direct equivalent of Java's `package`, so I did not include the package declaration. Also, in Python, we do not need to specify types for method parameters and return values like we do in Java.