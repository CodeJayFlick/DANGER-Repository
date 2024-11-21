Here is the translation of the Java code into Python:

```Python
class FunctionReturnTypeFieldLocation:
    def __init__(self, program=None, location_addr=None, function_addr=None, char_offset=0, signature="", return_type=""):
        self.program = program
        self.location_addr = location_addr
        self.function_addr = function_addr
        self.char_offset = char_offset
        self.signature = signature
        self.return_type_str = return_type

    def __init__(self, program=None, function_addr=None, col=0, signature="", return_type=""):
        self.__init__(program, None, function_addr, 0, signature, return_type)

    @classmethod
    def from_program_function_return(cls, program, function_addr, return_type):
        return cls(program, function_addr, 0, "", return_type)

    def __str__(self):
        return f"{super().__str__()}, Function Return Type: {self.return_type_str}"

    def get_return_type(self):
        return self.return_type_str

    def __hash__(self):
        result = super().__hash__()
        if self.return_type_str is None:
            result += 0
        else:
            result += hash(self.return_type_str)
        return result

    def __eq__(self, other):
        if self == other:
            return True
        if not super().__eq__(other):
            return False
        if isinstance(other, FunctionReturnTypeFieldLocation) and self.__class__ != other.__class__":
            return False
        if self.return_type_str is None:
            if other.return_type_str is not None:
                return False
        else:
            if self.return_type_str != other.return_type_str:
                return False
        return True

    def save_state(self, obj):
        super().save_state(obj)
        obj["return_type"] = self.return_type_str

    @classmethod
    def restore_state(cls, program, obj):
        instance = cls(program=program)
        instance.save_state(obj)
        instance.restore_state(program, obj)
```

Note that Python does not have direct equivalents for Java's `@Override` and `@param`, so I've omitted those. Also, the equivalent of Java's constructor is a special method in Python called `__init__`.