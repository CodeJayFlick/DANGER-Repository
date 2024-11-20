class ReturnParameterImpl:
    def __init__(self):
        pass

    @staticmethod
    def from_param(param: 'ReturnParameterImpl', program) -> None:
        if not isinstance(program, Program):
            raise InvalidInputException("Invalid program")
        super().__init__()

    @staticmethod
    def from_data_type(data_type: DataType, program) -> None:
        if not isinstance(program, Program):
            raise InvalidInputException("Invalid program")
        super().__init__()

    @staticmethod
    def from_stack_offset(data_type: DataType, stack_offset: int, program) -> None:
        if not isinstance(program, Program):
            raise InvalidInputException("Invalid program")
        super().__init__()

    @staticmethod
    def from_register(data_type: DataType, register: Register, program) -> None:
        if not isinstance(program, Program):
            raise InvalidInputException("Invalid program")
        super().__init__()

    @staticmethod
    def from_storage_addr(data_type: DataType, storage_addr: Address, program) -> None:
        if not isinstance(program, Program):
            raise InvalidInputException("Invalid program")
        super().__init__()

    @staticmethod
    def from_variable_storage(data_type: DataType, variable_storage: VariableStorage, program) -> None:
        if not isinstance(program, Program):
            raise InvalidInputException("Invalid program")
        super().__init__()

    @staticmethod
    def is_void_allowed() -> bool:
        return True

class InvalidInputException(Exception):
    pass

# Define other classes here like DataType, Register, Address, VariableStorage and Program.
