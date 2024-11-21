Here is the translation of the Java code to Python:
```
class PinSymbolCmd:
    def __init__(self, addr, name, pin):
        self.addr = addr
        self.name = name
        self.pin = pin
        self.message = None

    def apply_to(self, obj):
        if not isinstance(obj, Program):
            return False
        symbol_table = obj.get_symbol_table()
        symbol = symbol_table.get_global_symbol(name, addr)
        if symbol is None:
            self.message = f"Could not find symbol named {name} at address {addr}"
            return False
        symbol.set_pinned(pin)
        return True

    def get_status_msg(self):
        return self.message

    def get_name(self):
        return f"Set Pinned on {self.name}"

class Program:
    def __init__(self, *args):
        pass  # assuming this class is defined elsewhere in the codebase

    def get_symbol_table(self):
        raise NotImplementedError("get_symbol_table() must be implemented")

class SymbolTable:
    def __init__(self, *args):
        pass  # assuming this class is defined elsewhere in the codebase

    def get_global_symbol(self, name, addr):
        raise NotImplementedError("get_global_symbol() must be implemented")

    def set_pinned(self, pin):
        raise NotImplementedError("set_pinned() must be implemented")
```
Note that I've assumed some classes (`Program`, `SymbolTable`) are defined elsewhere in the codebase and haven't been included here. You'll need to implement these classes or replace them with equivalent Python constructs.

Also, I've used f-strings for string formatting, which is a feature introduced in Python 3.6+. If you're using an earlier version of Python, you can use the `format()` method instead.