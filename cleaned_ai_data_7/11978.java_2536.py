class BufferSubMemoryBlock:
    def __init__(self, adapter, record):
        super().__init__(adapter, record)
        buffer_id = record.get_int_value('SUB_INT_DATA1_COL')
        self.buf = adapter.get_buffer(buffer_id)

    @property
    def is_initialized(self):
        return True

    def get_byte(self, offset_in_mem_block):
        offset_in_sub_block = offset_in_mem_block - self.sub_block_offset
        return self.buf.getbyte(offset_in_sub_block)

    def get_bytes(self, offset_in_mem_block, b, off, len):
        offset_in_sub_block = offset_in_mem_block - self.sub_block_offset
        available = self.sub_block_length - offset_in_sub_block
        len = min(len, available)
        return self.buf.getbytes(offset_in_sub_block, b, off, len)

    def put_byte(self, offset_in_mem_block, byte):
        offset_in_sub_block = offset_in_mem_block - self.sub_block_offset
        self.buf.putbyte(offset_in_sub_block, byte)

    def put_bytes(self, offset_in_mem_block, b, off, len):
        offset_in_sub_block = offset_in_mem_block - self.sub_block_offset
        available = self.sub_block_length - offset_in_sub_block
        len = min(len, available)
        return self.buf.putbytes(offset_in_sub_block, b, off, len)

    def delete(self):
        self.buf.delete()
        super().delete()

    def join(self, block):
        if not isinstance(block, BufferSubMemoryBlock):
            return False
        other = block
        if other.sub_block_length + self.sub_block_length > 1073741824:
            return False
        self.buf.append(other.buf)
        self.set_length(self.sub_block_length + other.sub_block_length)
        adapter.delete_sub_block(other.record.get_key())
        return True

    def get_key(self):
        return record.get_key()

    def split(self, mem_block_offset):
        offset = int(mem_block_offset - self.sub_block_offset)
        new_length = self.sub_block_length - offset
        self.set_length(offset)
        record.set_long_value('SUB_LENGTH_COL', self.sub_block_length)
        adapter.update_sub_block_record(record)

        split = self.buf.split(offset)
        new_sub_record = adapter.create_sub_block_record(0, 0, new_length,
            'SUB_TYPE_BUFFER', split.get_id(), 0)

        return BufferSubMemoryBlock(adapter, new_sub_record)

    @property
    def description(self):
        return ""
