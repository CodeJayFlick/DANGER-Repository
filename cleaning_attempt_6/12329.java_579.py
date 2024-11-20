class IndexedDynamicDataType:
    def __init__(self, name: str, description: str, header: 'ghidra.program.model.data.DataType', 
                 keys: list, structs: list, index_offset: int, index_size: int, mask: int):
        self.description = description
        self.header = header
        self.keys = keys
        self.structs = structs
        self.index_offset = index_offset
        self.index_size = index_size
        self.mask = mask

    def get_all_components(self, buf: 'ghidra.program.model.mem.MemBuffer') -> list:
        memory = buf.get_memory()
        start = buf.get_address()

        # Find index
        index = self._get_index(memory, start + self.index_offset) & self.mask
        struct_index = None
        if len(self.keys) == 1:
            struct_index = int(index == self.keys[0])
        else:
            for key in self.keys:
                if index == key:
                    struct_index = self.table.get(key)
                    break

        if struct_index is None:
            print(f"ERROR: {self.name} at {start}")
            return []

        data_type = self.structs[struct_index]
        
        if data_type is None:
            print(f"ERROR: {self.name} at {start}")
            return []
        
        components = [ReadOnlyDataTypeComponent(self.header, self, len(data_type), 0, 0, data_type.get_name(), "")]

        try:
            count_size = len(data_type)
            offset = count_size
            buf = memory_buffer(memory, start + index_offset)
            buf.advance(count_size)
            dti = DataTypeInstance.get_data_type_instance(data_type, buf)
            if dti is None:
                print(f"ERROR: problem with data at {buf.get_address()}")
                return []
            
            len_ = dti.get_length()
            components.append(ReadOnlyDataTypeComponent(dti.get_data_type(), self, len_, 1, offset, f"{dti.get_data_type().get_name()}_{buf.get_address()}", ""))
        except AddressOverflowException as e:
            print(f"ERROR: problem with data at {buf.get_address()}")
            return []

        return components

    def get_description(self) -> str:
        return self.description

    def get_value(self, buf: 'ghidra.program.model.mem.MemBuffer', settings: 'ghidra.docking.settings.Settings', length: int) -> object:
        pass  # Not implemented in the original Java code

    def get_representation(self, buf: 'ghidra.program.model.mem.MemBuffer', settings: 'ghidra.docking.settings.Settings', length: int) -> str:
        return ""

    def get_mnemonic(self, settings: 'ghidra.program.model.data.Settings') -> str:
        return self.name

    def _get_index(self, memory: Memory, loc: Address) -> int:
        test = 0
        try:
            switch self.index_size:
                case 1:
                    test = Conv.byte_to_long(memory.get_byte(loc))
                    break
                case 2:
                    test = Conv.short_to_long(memory.get_short(loc))
                    break
                case 4:
                    test = memory.get_int(loc)
                    break
                case 8:
                    test = memory.get_long(loc)
                    break
        except MemoryAccessException as e:
            print(f"Unexpected Exception: {e.message}")

        return test

class ReadOnlyDataTypeComponent:
    def __init__(self, data_type: 'ghidra.program.model.data.DataType', parent: IndexedDynamicDataType, length: int, offset: int, index: int, name: str):
        self.data_type = data_type
        self.parent = parent
        self.length = length
        self.offset = offset
        self.index = index
        self.name = name

class MemoryBufferImpl:
    def __init__(self, memory: 'ghidra.program.model.mem.Memory', address: Address):
        pass  # Not implemented in the original Java code

class DataTypeInstance:
    @staticmethod
    def get_data_type_instance(data_type: 'ghidra.program.model.data.DataType', buf: MemoryBufferImpl) -> object:
        pass  # Not implemented in the original Java code
