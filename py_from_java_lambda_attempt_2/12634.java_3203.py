Here is a translation of the Java code into equivalent Python:

```Python
class HighFunctionSymbol:
    def __init__(self, addr, size, function):
        super().__init__(function.get_id(), "", DataType.DEFAULT, function)
        try:
            store = VariableStorage(get_program(), addr, size)
        except Exception as e:
            store = None  # or some default value
        entry = MappedEntry(self, store, None) if store else None
        self.add_map_entry(entry)

    def is_global(self):
        return True

    def get_namespace(self):
        func = function.get_function()
        namespace = func.get_parent_namespace()
        while func.is_thunk() and namespace.get_id() == Namespace.GLOBAL_NAMESPACE_ID:
            # Thunks can be in a different namespace than the thunked function.
            # We choose the thunk's namespace unless it is the global namespace
            func = func.get_thunked_function(False)
            namespace = func.get_parent_namespace()
        return namespace

    def save_xml(self, buf):
        entry = self.get_first_whole_map()
        if isinstance(entry, MappedEntry):
            min_addr = entry.get_storage().get_min_address()
            size = entry.get_size()
            func_string = function.build_function_xml(self.get_id(), get_namespace(), min_addr, size)
            buf.append(func_string)

class VariableStorage:
    def __init__(self, program, addr, size):
        pass  # or implement the constructor

class MappedEntry:
    def __init__(self, symbol, store, thunked_func):
        self.symbol = symbol
        self.store = store
        self.thunked_func = thunked_func

# Note: The following classes are not implemented in this translation.
class Namespace:
    GLOBAL_NAMESPACE_ID = None  # or some default value

class DataType:
    DEFAULT = None  # or some default value

class HighSymbol:
    def __init__(self, id, name, data_type, function):
        pass  # or implement the constructor

    def get_id(self):
        return self.id
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python.