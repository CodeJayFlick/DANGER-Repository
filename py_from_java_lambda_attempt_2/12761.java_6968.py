Here is the translation of the Java code into Python:

```Python
class EquateOperandFieldLocation:
    def __init__(self, program=None, addr=None, ref_addr=None, rep="", equate=None, op_index=0, sub_op_index=0, char_offset=0):
        super().__init__(program, addr, None, ref_addr, rep, op_index, sub_op_index, char_offset)
        
        if not isinstance(equate, dict) and equate is None:
            raise ValueError("Equate parameter cannot be null")

        self.equate = equate

    def __init_default(self):
        pass  # Default constructor needed for restoring an operand field location from XML.

    @property
    def equate(self):
        return self._equate

    @equate.setter
    def equate(self, value):
        if not isinstance(value, dict) and value is None:
            raise ValueError("Equate parameter cannot be null")
        
        self._equate = value

    def get_equate_value(self):
        if self.equate is None:
            return float('-inf')  # what to return?
        else:
            return self.equate.get('value', None)

    def get_references(self):
        if self.equate is None:
            return []
        else:
            return list(self.equate.values())

    def __str__(self):
        return super().__str__() + f", Equate value = {self.get_equate_value()}"

    def equals(self, obj):
        if super().equals(obj):  # @see java.lang.Object#equals(java.lang.Object)
            other = EquateOperandFieldLocation()
            other.equate = self._equate
            return str(other) == str(obj)
        else:
            return False

    def restore_state(self, program=None, obj={}):
        super().restore_state(program, obj)

        if 'EQUATE_VALUE' in obj and isinstance(obj['EQUATE_VALUE'], int):
            value = obj.pop('EQUATE_VALUE')
            equate_table = program.get_equate_table()
            self._equate = equate_table.get_equate(self.addr, self.op_index, value)
        else:
            raise ValueError("Invalid EQUATE VALUE")

    def save_state(self, obj={}):
        super().save_state(obj)

        if isinstance(self.equate, dict) and 'value' in self.equate:
            obj['EQUATE_VALUE'] = self.get_equate_value()
```

Note that Python does not have direct equivalent of Java's `@Override` annotation.