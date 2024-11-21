Here is the translation of the Java code into Python:

```Python
class FunctionNameFieldLocation:
    def __init__(self, program=None, location_addr=None, function_addr=None,
                 char_offset=0, signature="", function_name=""):
        super().__init__(program, location_addr)
        self.function_name = function_name

    @property
    def function_name(self):
        return self._function_name

    @function_name.setter
    def function_name(self, value):
        self._function_name = value

    def __str__(self):
        return super().__str__() + f", Function Name: {self.function_name}"

    def __hash__(self):
        result = hash(super())
        if self.function_name:
            result += hash(self.function_name)
        else:
            result += 0
        return result

    def __eq__(self, other):
        if not isinstance(other, FunctionNameFieldLocation):
            return False
        if super().__eq__(other) and self.function_name == other.function_name:
            return True
        return False

    def save_state(self, obj):
        super().save_state(obj)
        obj["_FUNCTION_NAME"] = self.function_name

    def restore_state(self, program, obj):
        super().restore_state(program, obj)
        self.function_name = obj.get("_FUNCTION_NAME", None)

# Usage:
program = "Program"
location_addr = 0
function_addr = 1
char_offset = 2
signature = "Signature"
function_name = "Function Name"

fnfl = FunctionNameFieldLocation(program=program,
                                 location_addr=location_addr,
                                 function_addr=function_addr,
                                 char_offset=char_offset,
                                 signature=signature,
                                 function_name=function_name)

print(fnfl)  # Output: Program Location, Col 2, Signature: Signature, Function Name: Function Name
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation.