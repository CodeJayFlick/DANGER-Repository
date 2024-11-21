class FunctionBodySizeTableColumn:
    def __init__(self):
        self.renderer = FunctionBodySizeRenderer()

    @property
    def column_name(self):
        return "Function Size"

    def get_value(self, row_object: 'ghidra.program.model.listing.Function', settings=None, program=None, service_provider=None) -> int:
        if not isinstance(row_object, ghidra.program.model.listing.Function):
            raise ValueError("Invalid function object")
        
        return row_object.get_body().get_num_addresses()

    def get_column_renderer(self) -> 'ghidra.util.table.column.GColumnRenderer[int]':
        return self.renderer

class FunctionBodySizeRenderer:
    pass
