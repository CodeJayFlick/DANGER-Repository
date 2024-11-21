class SymbolStringable:
    SHORT_NAME = "SYM"

    def __init__(self):
        self.symbol_name = None
        self.source_type = None

    def __init__(self, symbol_name: str, source_type: 'SourceType'):
        super().__init__()
        self.symbol_name = symbol_name
        self.source_type = source_type

    def get_display_string(self) -> str:
        return f"{self.symbol_name}" if self.symbol_name else ""

    def do_convert_to_string(self, program: object) -> str:
        return f"{self.symbol_name}{DELIMITER}{self.source_type.name()}"

    def do_restore_from_string(self, string: str, program: object):
        tokens = string.split(DELIMITER)
        self.symbol_name = tokens[0]
        self.source_type = SourceType[tokens[1]]

    @property
    def symbol_name(self) -> str:
        return self._symbol_name

    @property
    def source_type(self) -> 'SourceType':
        return self._source_type

    def __hash__(self):
        prime = 31
        result = 1
        if self.source_type is not None:
            result *= prime + hash(self.source_type)
        if self.symbol_name is not None:
            result *= prime + hash(self.symbol_name)
        return result

    def __eq__(self, other: object):
        if self is other:
            return True
        if other is None or type(self) != type(other):
            return False
        other = SymbolStringable(other)
        return SystemUtilities.is_equal(self.symbol_name, other.symbol_name) and \
               self.source_type == other.source_type

DELIMITER = ","
