Here's a translation of your Java code into equivalent Python:

```Python
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
```

Please note that this is a direct translation of your Java code into Python. It's not perfect, as there are some differences between the two languages (like static typing in Java vs dynamic typing in Python).