Here is the translation of the Java code to Python:
```
class ProgramProviderContext:
    def __init__(self, program: 'Program', addr: int):
        self.program = program
        self.addr = addr

    def get_data_type_components(self, start: int, end: int) -> list['DataTypeComponent']:
        result = []
        for offset in range(start, end + 1):
            dtc = self.get_data_type_component(offset)
            if dtc is None:
                break
            result.append(dtc)
            offset += dtc.length
        return [dtc.__class__(**vars(dtc)) for dtc in result]

    def get_data_type_component(self, offset: int) -> 'DataTypeComponent':
        data = self.get_data(offset)
        if data is None:
            return None

        dt = data.data_type
        length = data.length
        label = None
        symbol = data.primary_symbol
        if symbol and not symbol.is_dynamic():
            label = symbol.name
        comment = data.comment(CodeUnit.EOL_COMMENT)
        return DataTypeComponentImpl(dt, None, length, 0, offset, label, comment)

    def get_data(self, offset: int) -> 'Data':
        off_addr = self.addr + offset
        return self.program.listing.get_data_at(off_addr)

    def get_unique_name(self, base_name: str) -> str:
        return self.program.listing.data_type_manager.get_unique_name(CategoryPath.ROOT, base_name)
```
Note that I used the `__init__` method to initialize the object's attributes, and the rest of the methods are similar to their Java counterparts.

Also, since Python does not have a direct equivalent to Java's generics (type parameters), I did not include any type parameter declarations in the code. However, you can use Python's built-in `list` and `dict` types with specific types as arguments to achieve similar functionality.

Finally, note that some methods return lists of objects, which are represented using the `[]` syntax in Python.