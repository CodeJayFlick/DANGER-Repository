class LocalVariableInfo:
    @staticmethod
    def create_local_variable_info(local_variable):
        try:
            local_var_info = LocalVariableInfo(
                name=local_variable.name,
                first_use_offset=local_variable.first_use_offset,
                data_type=local_variable.data_type,
                variable_storage=local_variable.variable_storage,
                program=local_variable.program,
                source_type=local_variable.source_type
            )
            local_var_info.comment = local_variable.comment
            return local_var_info
        except Exception as e:
            raise AssertionError(f"Failed to clone local variable: {local_variable.function.name}:{local_variable.name}")

    @staticmethod
    def create_local_variable_info(local_variable_info_string, program):
        try:
            tokenizer = StringTokenizer(local_variable_info_string)
            tokenizer.nextToken()  # the first element is the class name

            manager_universal_id = int(tokenizer.nextToken())
            data_type_id = int(tokenizer.nextToken())
            data_type_name = tokenizer.nextToken()

            dt = get_data_type(program, manager_universal_id, data_type_id)
            if not (dt and dt.name == data_type_name):
                raise AssertionError(f"Data type name/ID mismatch {dt.name} doesn't match {data_type_name}")

            first_use_offset = int(tokenizer.nextToken())
            local_variable_name = tokenizer.nextToken()
            source_type = SourceType[tokenizer.nextToken()]
            comment = tokenizer.nextToken()

            storage = VariableStorage.deserialize(program, tokenizer.nextToken())

            localVarInfo = LocalVariableInfo(
                name=local_variable_name,
                first_use_offset=first_use_offset,
                data_type=dt,
                variable_storage=storage,
                program=program,
                source_type=source_type
            )
            localVarInfo.comment = comment

            return localVarInfo
        except Exception as e:
            raise AssertionError(f"Failed to deserialize local variable ({local_variable_info_string}): {e}")

    @staticmethod
    def get_data_type(program, manager_universal_id, data_type_id):
        dt_manager = program.data_type_manager
        actual_universal_id = dt_manager.universal_id.value
        if actual_universal_id != manager_universal_id:
            raise AssertionError(f"Provided data type manager ID of {actual_universal_id} doesn't matched saved ID of {manager_universal_id}")
        return dt_manager.get_data_type(data_type_id)

    def __init__(self, name, first_use_offset, data_type, variable_storage, program, source_type):
        super().__init__(name, first_use_offset, data_type, variable_storage, True, program, source_type)

    def convert_to_string(self):
        dt_manager = self.program.data_type_manager
        dt = self.data_type

        buffy = StringBuffer()
        buffy.append(self.__class__.__name__)
        buffy.append(Stringable.DELIMITER)
        buffy.append(str(dt_manager.universal_id.value))
        buffy.append(Stringable.DELIMITER)
        buffy.append(str(dt_manager.get_data_type_id(dt)))
        buffy.append(Stringable.DELIMITER)
        buffy.append(dt.name)
        buffy.append(Stringable.DELIMITER)
        buffy.append(str(self.first_use_offset))
        buffy.append(Stringable.DELIMITER)
        buffy.append(self.name)
        buffy.append(Stringable.DELIMITER)
        buffy.append(self.source_type.name())
        buffy.append(Stringable.DELIMITER)
        buffy.append(self.comment)
        buffy.append(Stringable.DELIMITER)
        buffy.append(self.variable_storage.get_serialization_string())

        return str(buffy)

    def create_local_variable(self, dest_function, destination_storage_address):
        try:
            offset = int(destination_storage_address.subtract(dest_function.entry_point))
            var = MyLocalVariable(
                name=self.name,
                first_use_offset=offset,
                data_type=self.data_type,
                serialized_storage=self.variable_storage.get_serialization_string(),
                program=dest_function.program,
                source_type=self.source_type
            )
            var.comment = self.comment

            return var
        except Exception as e:
            print(f"Unable to apply local variable '{self.name}' to function {dest_function.name}: {e}")
            return None

    class MyLocalVariable(LocalVariableImpl):
        def __init__(self, name, first_use_offset, data_type, serialized_storage, program, source_type):
            super().__init__(
                name=name,
                first_use_offset=first_use_offset,
                data_type=data_type,
                variable_storage=VariableStorage.deserialize(program, serialized_storage),
                True,
                program=program,
                source_type=source_type
            )
