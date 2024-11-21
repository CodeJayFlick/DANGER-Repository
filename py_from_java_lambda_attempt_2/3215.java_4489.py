Here is the translation of the given Java code into Python:

```Python
class DeleteLabelCmd:
    def __init__(self, addr, name, scope=None):
        self.addr = addr
        self.name = name
        self.scope = scope
        self.error_msg = None
        self.external_entry_cmd = None

    def apply_to(self, obj):
        program = Program(obj)
        symbol_table = program.get_symbol_table()
        symbol = symbol_table.get_symbol(name, addr, scope)

        if symbol is None:
            self.error_msg = f"Symbol {name} not found!"
            return False
        elif symbol.is_dynamic():
            self.error_msg = f"Deleting the dynamic symbol '{name}' @ {addr} is not allowed."
            return False

        if symbol.is_external_entry_point() and symbol.is_primary():
            if len(symbol_table.get_symbols(symbol.get_address())) == 1:
                self.external_entry_cmd = ExternalEntryCmd(addr, False)
                self.external_entry_cmd.apply_to(obj)

        success = symbol_table.remove_symbol_special(symbol)
        if not success:
            self.error_msg = f"Couldn't delete the symbol '{name}' @ {addr}."
        return success

    def get_name(self):
        return "Delete Label"

    def get_status_msg(self):
        return self.error_msg
```

Note that this translation assumes you have a `Program` class and an `ExternalEntryCmd` class defined elsewhere in your code.