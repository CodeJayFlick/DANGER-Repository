class DataTypeColumnTypeMapper:
    def convert(self, data_type: 'ghidra.program.model.data.DataType') -> str:
        return data_type.get_name()
