Here is the translation of the Java code into Python:

```Python
class FunctionParameterFieldLocation:
    def __init__(self, program=None, location_addr=None, function_addr=None,
                 char_offset=0, signature="", parameter=None):
        super().__init__(program, location_addr, function_addr, char_offset, signature)
        self.parameter = parameter

        if parameter is None:
            self.ordinal = -1
        else:
            self.ordinal = parameter.get_ordinal()

    def __init__(self):  # Default constructor needed for restoring a program location from XML
        pass

    @property
    def parameter(self):
        return self._parameter

    @parameter.setter
    def parameter(self, value):
        if isinstance(value, Parameter) or value is None:
            self._parameter = value
        else:
            raise ValueError("Invalid type for 'parameter'")

    def get_parameter(self):
        return self.parameter

    def get_ordinal(self):
        return self.ordinal

    def __eq__(self, other):
        if super().__eq__(other):  # Check equality with parent class
            if isinstance(other, FunctionParameterFieldLocation) and hasattr(other, 'ordinal'):
                return self.ordinal == other.ordinal
        return False

    def __str__(self):
        return f"{super().__str__()}, Function Parameter: {self.parameter}"

    def save_state(self, obj):
        super().save_state(obj)
        if isinstance(obj, dict):  # Assuming SaveState is a dictionary-like object
            obj['_FUNCTION_PARAMETER_ORDINAL'] = self.ordinal

    def restore_state(self, program, obj):
        super().restore_state(program, obj)
        if isinstance(obj, dict) and '_FUNCTION_PARAMETER_ORDINAL' in obj:
            self.ordinal = obj['_FUNCTION_PARAMETER_ORDINAL']
            function = program.get_function_at(self.function_addr)
            if function is not None:
                self.parameter = function.get_parameter(self.ordinal)

class Parameter:  # Assuming this class exists
    def get_ordinal(self):
        pass

# Example usage:
program = Program()  # Assuming a 'Program' class with necessary methods
location_addr = Address()
function_addr = Address()
signature = "example_signature"
parameter = Parameter()

fpfl = FunctionParameterFieldLocation(program, location_addr, function_addr,
                                       char_offset=0, signature=signature, parameter=parameter)
print(fpfl)  # Output: <FunctionSignatureFieldLocation>, Function Parameter: <Parameter>
```

Please note that I've made some assumptions about the classes and methods used in your code. For example, `Program`, `Address`, `Listing`, and `SaveState` are not defined here. You would need to define these yourself based on how you want them to work.

Also, this translation is just one possible way of translating Java into Python; there may be other ways that could also work depending on the specific requirements of your project.