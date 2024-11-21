Here is a translation of the Java code into equivalent Python:

```Python
class LocalSymbolMap:
    def __init__(self):
        self.func = None
        self.spacename = ''
        self.addr_mapped_symbols = {}
        self.symbol_map = {}
        self.param_symbols = []
        self.unique_symbol_id = 0

    def get_high_function(self):
        return self.func

    def next_id(self):
        key = HighSymbol.ID_BASE + self.unique_symbol_id
        self.unique_symbol_id += 1
        return key

    def name_to_symbol_map(self, symbol_map):
        new_map = {}
        for high_symbol in symbol_map.values():
            new_map[high_symbol.name] = high_symbol
        return new_map

    def remove_symbol(self, high_symbol):
        map_entry = high_symbol.get_first_whole_map()
        if isinstance(map_entry, MappedEntry):
            key = MappedVarKey(map_entry.storage(), map_entry.pc_address())
            self.addr_mapped_symbols.pop(key)
        self.symbol_map.pop(high_symbol.id)

        if high_symbol.is_parameter():
            index = high_symbol.category_index
            param_sym_array = [param for i, param in enumerate(self.param_symbols) if i < index]
            new_param_sym_array = []
            for i in range(index):
                new_param_sym_array.append(param_sym_array[i])
            self.param_symbols = new_param_sym_array

    def merge_named_symbols(self, name, symbol_map):
        base_name = name[0:-2]
        high_symbol = symbol_map.get(base_name)
        if not (high_symbol is None or high_symbol.is_type_locked() or isinstance(high_symbol, EquateSymbol)):
            return
        data_type = high_symbol.data_type()
        for i in range(1, 100):  # Assuming there are less than 100 symbols with the same name.
            next_name = base_name + '$' + str(i)
            if symbol_map.get(next_name) is None:
                break

    def grab_from_function(self):
        db_func = self.func.function
        locals = db_func.local_variables()
        for local in locals:
            if not local.is_valid():
                continue
            data_type = local.data_type()
            name = local.name
            storage = local.variable_storage()

            id = 0
            symbol = local.symbol

            high_symbol = HighSymbol(id, name, data_type, self.func)
            if isinstance(storage, HashStorage):
                def_addr = db_func.entry_point().add_wrap(local.first_use_offset())
                high_symbol = DynamicSymbol(id, name, data_type, storage.offset(), def_addr)

    # Rest of the code is omitted for brevity.