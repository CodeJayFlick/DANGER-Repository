class DisassembledFormatModel:
    BLOCK = "\u25A1"  # unicode for "WHITE SQUARE"

    def __init__(self):
        self.symbol_size = 1

    @property
    def name(self):
        return "Disassembled"

    @property
    def unit_byte_size(self):
        return 1

    def get_byte_offset(self, block: 'ByteBlock', position: int) -> int:
        return 0

    def get_column_position(self, block: 'ByteBlock', byte_offset: int) -> int:
        return 0

    @property
    def data_unit_symbol_size(self):
        return self.symbol_size

    def get_data_representation(self, block: 'ByteBlock', index: 'BigInteger') -> str:
        addr_str = block.get_location_representation(index)
        if addr_str is None:
            return "?"
        a = self.program.get_address_factory().get_address(addr_str)
        if a is None:
            return "."
        elif (self.listing.get_instruction_containing(a) or
              self.listing.get_defined_data_containing(a)):
            return "."
        else:
            return self.BLOCK

    def is_editable(self):
        return False

    def replace_value(self, block: 'ByteBlock', index: 'BigInteger', char_position: int, c: str) -> bool:
        if char_position != 0:
            return False
        cb = ord(c)
        if cb < 0x20 or cb == 0x7f:
            return False
        block.set_byte(index, cb)
        return True

    def get_group_size(self):
        return 0

    def set_group_size(self, group_size: int) -> None:
        raise NotImplementedError("groups are not supported")

    @property
    def unit_delimiter_size(self):
        return 0

    def validate_bytes_per_line(self, bytes_per_line: int) -> bool:
        return True

    def set_program(self, program: 'Program') -> None:
        self.program = program
        if program is not None:
            self.listing = program.get_listing()

    @property
    def help_location(self):
        return HelpLocation("ByteViewerPlugin", "Disassembled")

    def dispose(self) -> None:
        self.listing = None
        self.program = None


class ByteBlockAccessException(Exception):
    pass

class IndexOutOfBoundsException(Exception):
    pass

class UnsupportedOperationException(Exception):
    pass
