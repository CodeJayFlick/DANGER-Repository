class ByteBlockInfo:
    def __init__(self, block, offset):
        self.block = block
        self.offset = offset
        self.column = 0

    @property
    def column(self):
        return self._column

    @column.setter
    def column(self, value):
        self._column = value

    def get_block(self):
        return self.block

    def get_offset(self):
        return self.offset

    def __str__(self):
        return f"ByteBlockInfo: block start={self.block}, offset={self.offset}, column={self.column}"

    def __hash__(self):
        return hash((self.block, self.offset, self.column))

    def __eq__(self, other):
        if not isinstance(other, ByteBlockInfo):
            return False

        if id(self) == id(other):
            return True

        if (isinstance(other, type(self)) and
                self.block == other.block and
                self.offset == other.offset and
                self.column == other.column):
            return True

        return False


# Example usage:
class ByteBlock:
    def __init__(self, location_representation):
        self.location_representation = location_representation

    @property
    def get_location_representation(self):
        return self._location_representation

    @get_location_representation.setter
    def set_location_representation(self, value):
        self._location_representation = value


block1 = ByteBlock("some block")
offset1 = 12345678901234567890
info1 = ByteBlockInfo(block1, offset1)

print(info1)
