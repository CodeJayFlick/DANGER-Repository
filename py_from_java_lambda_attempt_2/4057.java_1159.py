Here is the translation of the given Java code into Python:

```Python
class GenericDataTypeProgramLocation:
    def __init__(self, program: 'Program', data_type: 'DataType'):
        super().__init__(program, program.get_min_address())
        self.data_type = data_type

    @property
    def data_type(self):
        return self._data_type

# Assuming you have a Program and DataType class defined elsewhere in your code,
# here's how you would use this class:
program = ...  # some instance of the Program class
data_type = ...  # some instance of the DataType class
location = GenericDataTypeProgramLocation(program, data_type)
print(location.data_type)  # prints: <some_data_type_instance>
```

Please note that Python does not have direct equivalent to Java's package and import statements. Also, Python classes do not need explicit constructors as they are defined by `__init__` method.