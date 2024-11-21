Here is the translation of the given Java code into equivalent Python:

```Python
class SymbolTableCommand:
    def __init__(self):
        pass

    @staticmethod
    def create_symbol_table_command(reader, header) -> 'SymbolTableCommand':
        symbol_table_command = reader.create(SymbolTableCommand)
        symbol_table_command.init_symbol_table_command(reader, header)
        return symbol_table_command

    def init_symbol_table_command(self, reader, header):
        self.init_load_command(reader)

        self.symoff = reader.read_next_int()
        self.nsyms = reader.read_next_int()
        self.stroff = reader.read_next_int()
        self.strsize = reader.read_next_int()

        index = reader.get_pointer_index()
        reader.set_pointer_index(header.start_index + self.symoff)
        
        nlist_list = []
        for i in range(self.nsyms):
            nlist_list.append(NList.create_nlist(reader, header.is_32bit()))
            
        sorted_list = sorted(nlist_list, key=lambda x: x.get_string_table_index())
        string_table_offset = self.stroff
        for nlist in sorted_list:
            nlist.init_string(reader, string_table_offset)
            string_table_offset += len(nlist.get_string())

        self.symbols = nlist_list

    def get_symbol_offset(self):
        return self.symoff

    def get_number_of_symbols(self):
        return self.nsyms

    def get_string_table_offset(self):
        return self.stroff

    def get_string_table_size(self):
        return self.strsize

    def get_symbols(self):
        return self.symbols

    def get_symbol_at(self, index):
        if (index & DynamicSymbolTableConstants.INDIRECT_SYMBOL_LOCAL) != 0 or \
           (index & DynamicSymbolTableConstants.INDIRECT_SYMBOL_ABS) != 0:
            return None
        if index > len(self.symbols):
            Msg.error(self, f"Attempt to get symbols at {hex(index)}")
            return None

        return self.symbols[index]

    def to_data_type(self):
        struct = StructureDataType(get_command_name(), 0)
        struct.add(DWORD, "cmd", None)
        struct.add(DWORD, "cmdsize", None)
        struct.add(DWORD, "symoff", None)
        struct.add(DWORD, "nsyms", None)
        struct.add(DWORD, "stroff", None)
        struct.add(DWORD, "strsize", None)

    def get_command_name(self):
        return "symtab_command"

class NList:
    @staticmethod
    def create_nlist(reader, is_32bit) -> 'NList':
        pass

    def init_string(self, reader, string_table_offset):
        pass

    def get_string_table_index(self):
        pass

    def to_data_type(self):
        pass

    def get_value(self):
        pass

class StructureDataType:
    def __init__(self, name, length):
        self.name = name
        self.length = length

    def add(self, data_type, field_name, default_value=None):
        pass

    def set_category_path(self, category_path):
        pass

class MachHeader:
    @property
    def start_index(self) -> int:
        return 0

    @property
    def is_32bit(self) -> bool:
        return False

class FlatProgramAPI:
    def create_data(self, address: Address, data_type: DataType) -> 'Data':
        pass

    def create_fragment(self, parent_module: ProgramModule, name: str, start_address: Address, length: int):
        pass

    def set_reference_primary(self, reference: Reference, primary: bool):
        pass

class Data:
    @property
    def value(self) -> object:
        return None

class Address:
    def get_new_address(self, offset: int) -> 'Address':
        pass

class ProgramModule:
    pass

class TaskMonitor:
    def is_cancelled(self) -> bool:
        return False

class MessageLog:
    def append_msg(self, message: str):
        pass
```

Please note that the above Python code does not include all the classes and methods present in the original Java code. It only includes those parts which are necessary for translation purposes.