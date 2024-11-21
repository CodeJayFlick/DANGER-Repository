Here is the translation of the Java code into Python:

```Python
class OldFunctionDataDB:
    def __init__(self, function_manager: 'OldFunctionManager', address_map: 'AddressMap',
                 db_record: 'DBRecord', body_view: 'AddressSetView'):
        self.function_manager = function_manager
        self.address_map = address_map
        self.db_record = db_record
        self.body = body_view

        entry_point = self.address_map.decode_address(db_record.get_key())
        program = self.function_manager.get_program()
        self.function_adapter = self.function_manager.get_function_adapter()
        self.register_adapter = self.function_manager.get_register_variable_adapter()

    def get_address_map(self):
        return self.address_map

    def get_function_manager(self):
        return self.function_manager

    def get_program(self):
        return self.program

    def get_comment(self) -> str:
        code_unit = self.program.get_code_manager().get_code_unit_containing(entry_point)
        return code_unit.get_comment()

    def get_comment_as_array(self) -> list[str]:
        return [line.strip() for line in self.get_comment().split('\n')]

    def get_repeatable_comment(self) -> str:
        comment = db_record.get_string('REPEATABLE_COMMENT_COL')
        return comment

    def get_repeatable_comment_as_array(self) -> list[str]:
        lines = []
        for line in self.get_repeatable_comment().split('\n'):
            if line.strip():
                lines.append(line)
        return lines

    def get_entry_point(self):
        return entry_point

    def get_body(self):
        if not self.body:
            body_view = self.function_manager.get_function_body(db_record.get_key())
            self.body = body_view
        return self.body

    def get_return_type(self) -> 'DataType':
        type_id = db_record.get_long_value('RETURN_DATA_TYPE_ID_COL')
        data_type = self.function_manager.get_data_type(type_id)
        if not data_type:
            data_type = DataType.DEFAULT
        return data_type

    def get_stack_frame(self):
        return self.frame

    def get_stack_depth_change(self) -> int:
        value = db_record.get_int_value('STACK_DEPTH_COL')
        return value

    def is_stack_depth_valid(self) -> bool:
        if self.get_stack_depth_change() > 0xffffff:
            return False
        return True

    def get_stack_param_offset(self):
        return db_record.get_int_value('STACK_PARAM_OFFSET_COL')

    def get_stack_return_offset(self):
        return db_record.get_int_value('STACK_RETURN_OFFSET_COL')

    def get_stack_local_size(self) -> int:
        return db_record.get_int_value('STACK_LOCAL_SIZE_COL')

    def load_register_parameter_list(self):
        if self.reg_params is not None:
            return
        self.reg_params = []
        try:
            keys = self.register_adapter.get_register_variable_keys(db_record.get_key())
            for i, key in enumerate(keys):
                var_rec = self.register_adapter.get_register_variable_record(key)
                self.reg_params.append(self.get_register_parameter(var_rec, i))
        except IOException as e:
            self.function_manager.db_error(e)

    def get_register_parameter(self, db_record: 'DBRecord', ordinal: int) -> 'Parameter':
        name = db_record.get_string('REG_VAR_NAME_COL')
        data_type_id = db_record.get_long_value('REG_VAR_DATA_TYPE_ID_COL')
        reg_name = db_record.get_string('REG_VAR_REGNAME_COL')

        try:
            storage = VariableStorage.BAD_STORAGE
            register = self.function_manager.get_program().get_register(reg_name)
            if not register:
                raise InvalidInputException()
            else:
                storage = VariableStorage(self.program, register.address, data_type_id)

            return OldFunctionParameter(name, ordinal, data_type_id, storage, self.program,
                                          SourceType.USER_DEFINED)
        except (InvalidInputException):
            # should not occur
            pass

    def get_parameters(self) -> list['Parameter']:
        if not hasattr(self, 'reg_params'):
            self.load_register_parameter_list()

        parameters = []
        ordinal = 0
        for param in self.reg_params:
            parameters.append(param)
            ordinal += 1

        try:
            stack_params = self.frame.get_parameters()
            for i, param in enumerate(stack_params):
                parameters.append(OldFunctionParameter(param.name, ordinal + i,
                                                         param.data_type_id, param.storage,
                                                         self.program, SourceType.USER_DEFINED))
        except InvalidInputException as e:
            raise RuntimeError(e)

        return parameters

    def get_key(self) -> int:
        return db_record.get_key()


class OldFunctionParameter(ParameterImpl):
    def __init__(self, name: str, ordinal: int, data_type_id: int,
                 storage: 'VariableStorage', program: 'Program',
                 source_type: 'SourceType'):
        super(name, ordinal, data_type_id, storage, True, program, source_type)
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an interpretation and might require some adjustments based on the actual usage in your project.

Also, please be aware that Python does not have built-in support for checked exceptions like `IOException` or `InvalidInputException`. These are typically handled using try-except blocks instead.