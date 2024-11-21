class AddStackParameterCommand:
    def __init__(self, function, stack_offset, name, data_type, ordinal, source):
        self.stack_offset = stack_offset
        self.name = name
        self.data_type = data_type
        self.ordinal = ordinal
        self.source = source

    def get_parameter(self, program):
        return ParameterImpl(name=self.name, data_type=self.data_type, offset=self.stack_offset, program=program)

class ParameterImpl:
    def __init__(self, name, data_type, offset, program):
        self.name = name
        self.data_type = data_type
        self.offset = offset
        self.program = program

def main():
    # Example usage of the class
    function = "ExampleFunction"
    stack_offset = 10
    name = "exampleParameter"
    data_type = "int"  # Assuming this is a valid Python type for now, you might need to use something like 'int' or 'float'
    ordinal = 1
    source = "Source"

    command = AddStackParameterCommand(function=function, stack_offset=stack_offset, name=name, data_type=data_type, ordinal=ordinal, source=source)
    parameter = command.get_parameter(program="ExampleProgram")
    print(f"Created a new function stack parameter: {parameter.name} of type {data_type} at offset {stack_offset}")

if __name__ == "__main__":
    main()
