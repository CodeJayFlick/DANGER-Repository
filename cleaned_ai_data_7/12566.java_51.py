class ParameterImpl:
    def __init__(self):
        pass

    @staticmethod
    def construct_parameter(name: str, ordinal: int, data_type: 'DataType', storage=None, stack_offset=None,
                             register=None, force=False, program='Program', source_type='SourceType'):
        if not isinstance(data_type, DataType) or not isinstance(program, Program) or \
           not isinstance(source_type, SourceType):
            raise InvalidInputException("Invalid input")
        return ParameterImpl(name, ordinal, data_type, storage, stack_offset, register, force, program, source_type)

    @staticmethod
    def construct_parameter_from_another(param: 'Parameter', program='Program'):
        if not isinstance(program, Program) or not isinstance(param, Parameter):
            raise InvalidInputException("Invalid input")
        return ParameterImpl(param.name(), param.ordinal(), param.data_type(), None, None, None, False, program,
                              param.source_type())

    def __init__(self, name: str, ordinal: int, data_type: 'DataType', storage=None, stack_offset=None,
                 register=None, force=False, program='Program', source_type='SourceType'):
        if not isinstance(data_type, DataType) or not isinstance(program, Program) or \
           not isinstance(source_type, SourceType):
            raise InvalidInputException("Invalid input")
        self.ordinal = ordinal
        super().__init__(name, data_type, storage, stack_offset, register, force, program)

    def has_default_name(self) -> bool:
        return SymbolUtilities.is_default_parameter_name(self.name())

    @property
    def ordinal(self):
        return self._ordinal

    @ordinal.setter
    def ordinal(self, value: int):
        if not isinstance(value, int):
            raise InvalidInputException("Invalid input")
        self._ordinal = value

    @property
    def first_use_offset(self) -> int:
        return 0

    def get_data_type(self) -> 'DataType':
        dt = super().get_formal_data_type()
        var_storage = self.get_variable_storage()
        if var_storage.is_forced_indirect():
            program = self.get_program()
            data_type_manager = program.get_data_type_manager()
            ptr_size = var_storage.size()
            if ptr_size != data_type_manager.get_pointer_size():
                dt = data_type_manager.get_pointer(dt, ptr_size)
            else:
                dt = data_type_manager.get_pointer(dt)
        return dt

    def get_formal_data_type(self) -> 'DataType':
        return super().get_data_type()

    def is_forced_indirect(self) -> bool:
        var_storage = self.get_variable_storage()
        if var_storage is None:
            return False
        else:
            return var_storage.is_forced_indirect()

    def is_auto_parameter(self) -> bool:
        var_storage = self.get_variable_storage()
        if var_storage is None:
            return False
        else:
            return var_storage.is_auto_storage()

    def get_auto_parameter_type(self) -> 'AutoParameterType':
        var_storage = self.get_variable_storage()
        if var_storage is None:
            return None
        else:
            return var_storage.get_auto_parameter_type()


class AutoParameterType:
    pass


class SourceType:
    pass


class Program:
    pass


class DataTypeManager:
    def get_pointer_size(self) -> int:
        pass

    def get_pointer(self, data_type: 'DataType', ptr_size: int = None) -> 'DataType':
        pass
