class IsFunctionVarargsTableColumn:
    def get_column_name(self):
        return "Varargs"

    def get_value(self, row_object: 'ghidra.program.model.listing.Function', settings=None, data=None, service_provider=None) -> bool:
        if not isinstance(row_object, ghidra.program.model.listing.Function):
            raise ValueError("Invalid row object")
        return row_object.has_var_args()
