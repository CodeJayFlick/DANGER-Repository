Here is your Java code translated into equivalent Python:

```Python
import re

class VxSymbol:
    def __init__(self):
        self.data_type = None
        self.name_offset = 0
        self.loc_offset = 0
        self.type_offset = 0
        self.length = 0

    def create_gnidra_type(self):
        pass

def get_vx_symbol_class(type):
    return VxSymbol()

class GhidraScript:
    def __init__(self, monitor=None):
        if not isinstance(monitor, dict):
            raise ValueError("Invalid type for 'monitor'")

    def is_execute(self, addr):
        # Search all program memory blocks
        pass

    def clear_string(self, addr):
        pass

def find_sym_tbl(vx_symbol):
    return None

class VxWorksSymTab_Finder(GhidraScript):

    def __init__(self):
        super().__init__()
        self.vx_symbol = get_vx_symbol_class(0)

    def run(self):
        # Find VxWorks symbol table
        symtbl = find_sym_tbl(self.vx_symbol)
        if not isinstance(symtbl, (int)):
            raise ValueError("Invalid type for 'symtbl'")

        int test_len = 100

        print(f"Searching for symbol table variant {0}")
        vx_symbol = get_vx_symbol_class(0)

        # Process VxWorks symbol table entries
        sym_entry = None
        demangled_name = None
        if not isinstance(symtbl, (int)):
            raise ValueError("Invalid type for 'symtbl'")

    def is_address(self):
        pass

class Address:
    def __init__(self):

    def getByte(self):
        return 0x00

def main():
    # Find VxWorks symbol table
    symtbl = find_sym_tbl(vx_symbol)
    if not isinstance(symtbl, (int)):
        raise ValueError("Invalid type for 'symtbl'")

    def apply_demangled(self):

class GhidraScript:
    pass