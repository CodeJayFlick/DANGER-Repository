class FunctionParameterTypeLocationDescriptor:
    def __init__(self, location: 'ProgramLocation', program: 'Program'):
        super().__init__(location, program)
        
        if not isinstance(location, FunctionParameterFieldLocation):
            raise AssertionError("Unexpected ProgramLocation type - Cannot create a LocationDescriptor for type: {}".format(location))

    @property
    def generate_label(self) -> str:
        return self.get_data_type_name()

    @property
    def get_data_type_name(self) -> str:
        parameter_location = cast(FunctionParameterFieldLocation, self.location)
        return parameter_location.parameter.data_type.display_name

    @property
    def source_data_type(self) -> 'DataType':
        return (cast(FunctionParameterFieldLocation, self.location).parameter.data_type)

class ProgramLocation:
    pass

class FunctionParameterFieldLocation(ProgramLocation):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parameter = None
        self.data_type = None

class DataType:
    @property
    def display_name(self) -> str:
        return ""

# Example usage:
location = FunctionParameterFieldLocation()
program = Program()

descriptor = FunctionParameterTypeLocationDescriptor(location, program)

print(descriptor.generate_label())  # prints the data type name
