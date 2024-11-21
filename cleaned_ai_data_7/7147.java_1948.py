import io


class TryItem:
    def __init__(self):
        self.start_address = None
        self.instruction_count = None
        self.handler_offset = None

    @classmethod
    def from_reader(cls, reader: 'BinaryReader') -> 'TryItem':
        try:
            start_address = int.from_bytes(reader.read(4), byteorder='little')
            instruction_count = int.from_bytes(reader.read(2), byteorder='little')
            handler_offset = int.from_bytes(reader.read(2), byteorder='little')

            return cls(start_address, instruction_count, handler_offset)
        except Exception as e:
            raise IOError(str(e))

    def __init__(self, start_address: int, instruction_count: short, handler_offset: short):
        self.start_address = start_address
        self.instruction_count = instruction_count
        self.handler_offset = handler_offset

    @property
    def start_address(self) -> int:
        return self._start_address

    @start_address.setter
    def start_address(self, value: int):
        if not isinstance(value, int):
            raise TypeError('Start address must be an integer')
        self._start_address = value

    @property
    def instruction_count(self) -> short:
        return self._instruction_count

    @instruction_count.setter
    def instruction_count(self, value: short):
        if not isinstance(value, int) or 0 > value > 65535:
            raise ValueError('Instruction count must be a positive integer less than 2^16')
        self._instruction_count = value

    @property
    def handler_offset(self) -> short:
        return self._handler_offset

    @handler_offset.setter
    def handler_offset(self, value: short):
        if not isinstance(value, int) or 0 > value > 65535:
            raise ValueError('Handler offset must be a positive integer less than 2^16')
        self._handler_offset = value


class BinaryReader(io.IOBase):
    pass

# Example usage
reader = BinaryReader()
try_item = TryItem.from_reader(reader)
print(try_item.start_address, try_item.instruction_count, try_item.handler_offset)

