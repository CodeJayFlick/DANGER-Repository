class LabelFieldLocation:
    def __init__(self):
        pass

    @staticmethod
    def create(program: 'Program', addr: 'Address', component_path=None, label='', namespace=None, row=0, char_offset=0) -> 'LabelFieldLocation':
        return LabelFieldLocation(program, addr, component_path, label, namespace, row, char_offset)

    def __init__(self, program: 'Program', addr: 'Address', component_path=None, label='', namespace=None, row=0, char_offset=0):
        super().__init__(program, addr, component_path, row, 0, char_offset)
        if namespace is None or namespace.is_global:
            self.symbol_path = SymbolPath(label)
        else:
            self.symbol_path = SymbolPath(namespace.get_symbol(), label)

    @staticmethod
    def create_with_namespace(program: 'Program', addr: 'Address', label='', namespace=None) -> 'LabelFieldLocation':
        return LabelFieldLocation.create(program, addr, None, label, namespace, 0, 0)

    @staticmethod
    def create_with_row_and_char_offset(s: 'Symbol') -> 'LabelFieldLocation':
        return LabelFieldLocation.create(s.get_program(), s.get_address(), None, s.get_name(), s.get_parent_namespace(), s.get_row(), s.get_char_offset())

    def get_name(self) -> str:
        return self.symbol_path.name

    def get_symbol(self) -> 'Symbol' or None:
        symbols = NamespaceUtils.get_symbols(self.symbol_path, self.program)
        for symbol in symbols:
            if symbol.address == self.addr:
                return symbol
        return None

    def get_symbol_path(self) -> 'SymbolPath':
        return self.symbol_path

    def __str__(self):
        return super().__str__() + f", Label = {self.symbol_path.path}"

    def __hash__(self):
        prime = 31
        result = hash(super())
        result *= prime
        result += self.symbol_path.__hash__()
        return result

    def __eq__(self, other: 'LabelFieldLocation') -> bool:
        if self is other:
            return True
        if not super().__eq__(other):
            return False
        if type(self) != type(other):
            return False
        return self.symbol_path == other.symbol_path

    def save_state(self, obj):
        super().save_state(obj)
        obj.put_strings("_SYMBOL_PATH", self.symbol_path.as_array())

    @classmethod
    def restore_state(cls, program: 'Program', obj) -> None:
        super().restore_state(program, obj)
        symbol_path_array = obj.get_strings("_SYMBOL_PATH")
        if symbol_path_array is not None:
            self.symbol_path = SymbolPath(symbol_path_array)
