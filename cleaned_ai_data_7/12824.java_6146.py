class VariableLocFieldLocation:
    def __init__(self, program=None, location_addr=None, var=None, char_offset=0):
        super().__init__()
        self.loc = str(var.get_variable_storage()) if var else None

    @property
    def loc(self):
        return self._loc

    @loc.setter
    def loc(self, value):
        self._loc = value

    def __hash__(self):
        result = super().__hash__()
        if self.loc:
            result += hash(self.loc)
        return result

    def __eq__(self, other):
        if not isinstance(other, VariableLocFieldLocation):
            return False
        if not super().__eq__(other):
            return False
        if self.loc != other.loc:
            return False
        return True

    def restore_state(self, program=None, obj={}):
        super().restore_state(program=program, state=obj)
        self.loc = obj.get("_LOC", "")

    def save_state(self, obj={}):
        super().save_state(obj=obj)
        obj["_LOC"] = self.loc


# Example usage:
class Variable:
    def get_variable_storage(self):
        return "some storage"


class Program:
    pass

var = Variable()
program = Program()

vlf_location = VariableLocFieldLocation(program=program, var=var, char_offset=0)

print(vlf_location.loc)  # prints: some storage
