class OmfIteratedData:
    MAX_ITERATED_FILL = 0x100000
    
    def __init__(self, reader):
        self.read_record_header(reader)
        max = reader.tell() + self.get_record_length() - 1
        has_big_fields = self.has_big_fields()
        self.segment_index = OmfRecord.read_index(reader)
        self.data_offset = OmfRecord.read_int2_or_4(reader, has_big_fields)
        block_list = []
        while reader.tell() < max:
            block = DataBlock.read(reader, has_big_fields)
            block_list.append(block)
        self.read_check_sum_byte(reader)
        self.datablock = [block for block in block_list]

    def get_segment_index(self):
        return self.segment_index

    @property
    def data_offset_(self):
        return self.data_offset

    def is_all_zeroes(self):
        for i, block in enumerate(self.datablock):
            if not block.is_all_zeroes():
                return False
        return True

    @property
    def length_(self):
        total_length = 0
        for block in self.datablock:
            total_length += block.length_
        return total_length

    def get_byte_array(self, reader):
        buffer_size = self.length_
        if buffer_size > OmfIteratedData.MAX_ITERATED_FILL:
            raise IOException("Iterated data-block is too big")
        buffer = bytearray(buffer_size)
        pos = 0
        for block in self.datablock:
            pos = block.fill_buffer(buffer, pos)
        return bytes(buffer)

    def compare_to(self, o):
        other_offset = o.data_offset_
        if self.data_offset_ == other_offset:
            return 0
        elif self.data_offset_ < other_offset:
            return -1
        else:
            return 1


class DataBlock:
    def __init__(self):
        pass

    @classmethod
    def read(cls, reader, has_big_fields):
        block = cls()
        block.repeat_count = OmfRecord.read_int2_or_4(reader, has_big_fields)
        block.block_count = reader.read_next_short() & 0xffff
        if block.block_count == 0:
            size = reader.read_next_byte() & 0xff
            block.simple_block = bytearray(size)
            for i in range(size):
                block.simple_block[i] = reader.read_next_byte()
        else:
            block.nested_block = [DataBlock().read(reader, has_big_fields) for _ in range(block.block_count)]
        return block

    def fill_buffer(self, buffer, pos):
        for _ in range(self.repeat_count):
            if self.simple_block is not None:
                for element in self.simple_block:
                    buffer[pos] = element
                    pos += 1
            elif self.nested_block is not None:
                for nested_block in self.nested_block:
                    pos = nested_block.fill_buffer(buffer, pos)
        return pos

    @property
    def length_(self):
        if self.simple_block is not None:
            return len(self.simple_block)
        else:
            total_length = 0
            for block in self.nested_block:
                total_length += block.length_
            return total_length * self.repeat_count

    def is_all_zeroes(self):
        if self.simple_block is not None:
            for element in self.simple_block:
                if element != 0:
                    return False
        elif self.nested_block is not None:
            for nested_block in self.nested_block:
                if not nested_block.is_all_zeroes():
                    return False
        return True


class OmfRecord:
    @classmethod
    def read_index(cls, reader):
        # implementation missing

    @classmethod
    def read_int2_or_4(cls, reader, has_big_fields):
        # implementation missing

    @classmethod
    def read_check_sum_byte(cls, reader):
        # implementation missing


class IOException(Exception):
    pass
