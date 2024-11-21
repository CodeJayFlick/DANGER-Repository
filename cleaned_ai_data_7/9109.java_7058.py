class AbstractFunctionParameterMarkupItemTest:
    def __init__(self):
        pass

    # Private Methods
    def create_byte_data_type(self, program):
        data_manager = program.data_type_manager()
        byte_data_type = ByteDataType(data_manager)
        return data_manager.add_data_type(byte_data_type)

    def create_int_data_type(self, program):
        transaction = -1
        try:
            transaction = program.start_transaction("Test  - Create Data Type")
            data_manager = program.data_type_manager()
            int_data_type = IntegerDataType(data_manager)
            return data_manager.add_data_type(int_data_type)
        finally:
            program.end_transaction(transaction, True)

    def add_register_parameter(self, function, data_type):
        try:
            transaction = function.get_program().start_transaction("Test  - Add Parameter")
            register = Register("EAX", function.get_program())
            parameter = ParameterImpl(VTTestUtils.random_string(), data_type, register)
            return function.add_parameter(parameter, SourceType.USER_DEFINED)
        finally:
            function.get_program().end_transaction(transaction, True)

    def add_memory_parameter(self, function, data_type):
        try:
            transaction = function.get_program().start_transaction("Test  - Add Parameter")
            parameter = ParameterImpl(VTTestUtils.random_string(), data_type, function.entry_point())
            return function.add_parameter(parameter, SourceType.USER_DEFINED)
        finally:
            function.get_program().end_transaction(transaction, True)

    def add_stack_parameter(self, function, data_type):
        try:
            transaction = function.get_program().start_transaction("Test  - Add Parameter")
            parameter_count = function.parameter_count()
            stack_offset = function.stack_frame().parameter_offset
            if parameter_count != 0:
                parameters = function.parameters()
                for param in parameters:
                    data_type_param = param.data_type
                    stack_offset += data_type_param.length
            else:
                pass

            parameter = ParameterImpl(VTTestUtils.random_string(), data_type, stack_offset)
            return function.add_parameter(parameter, SourceType.USER_DEFINED)
        finally:
            function.get_program().end_transaction(transaction, True)

    def remove_parameters(self, function):
        parameters = function.parameters()

        try:
            transaction = function.get_program().start_transaction("Test  - Remove Parameters")
            for param in parameters:
                function.remove_parameter(param.ordinal)
        finally:
            function.get_program().end_transaction(transaction, True)


class ByteDataType:
    pass

class IntegerDataType:
    pass

class ParameterImpl:
    def __init__(self, name, data_type, register=None):
        self.name = name
        self.data_type = data_type
        if register is not None:
            self.register = register


# Usage example:

program = ProgramDB()  # Assuming this class exists in Python.
test = AbstractFunctionParameterMarkupItemTest()
function = Function(program)
data_type = test.create_byte_data_type(program)  # or create_int_data_type

parameter1 = test.add_register_parameter(function, data_type)
parameter2 = test.add_memory_parameter(function, data_type)
parameter3 = test.add_stack_parameter(function, data_type)

test.remove_parameters(function)
