class TraceBasedDataTypeManager:
    def __init__(self):
        pass  # No equivalent constructor in Python

    def get_program(self) -> 'ghidra.trace.model.program.TraceProgramView':
        return self.get_trace().get_program_view()

    def get_trace(self) -> 'ghidra(trace).model.Trace':
        raise NotImplementedError("Method not implemented")

    def resolve_type(self, data_type: 'DataType', handler: 'DataTypeConflictHandler') -> 'T':
        """TODO: Petition to have this replace
            {@link TraceBasedDataTypeManager#resolve( DataType, DataTypeConflictHandler)}
        """
        return self.resolve(data_type, handler)

    def add_type(self, data_type: 'DataType', handler: 'DataTypeConflictHandler') -> 'T':
        """TODO: Petition to have this replace
            {@link TraceBasedDataTypeManager#addDataType(DataType, DataTypeConflictHandler)}
        """
        return self.add_data_type(data_type, handler)

    def replace_type(self, existing_dt: 'DataType', replacement_dt: 'T',
                     update_category_path: bool) -> 'T':
        """TODO: Petition to have this replace
            {@link TraceBasedDataTypeManager#replaceDataType(DataType, DataType, boolean)}
        """
        return self.replace_data_type(existing_dt, replacement_dt, update_category_path)
