class FileBytes:
    def __init__(self, adapter, record):
        self.adapter = adapter
        self.id = record['id']
        self.filename = record['filename']
        self.file_offset = record['file_offset']
        self.size = record['size']
        self.refresh(record)

    def refresh(self, record):
        if (record['filename'] != self.filename or 
            record['file_offset'] != self.file_offset or
            record['size'] != self.size):
            return False

        field = record['field_value'](FileBytesAdapter.BUF_IDS_COL)
        buffer_ids = [int(x) for x in field]
        self.original_buffers = [self.adapter.get_buffer(id) for id in buffer_ids]

        field = record['field_value'](FileBytesAdapter.LAYERED_BUF_IDS_COL)
        buffer_ids = [int(x) for x in field]
        self.layered_buffers = [self.adapter.get_buffer(id, original_buffer) 
                                for id, original_buffer in zip(buffer_ids, self.original_buffers)]
        return True

    def get_id(self):
        return self.id

    def get_filename(self):
        return self.filename

    def get_file_offset(self):
        return self.file_offset

    def get_size(self):
        return self.size

    def get_modified_byte(self, offset):
        check_valid()
        if offset < 0 or offset >= self.size:
            raise IndexError
        return self.get_byte(self.layered_buffers, offset)

    def get_original_byte(self, offset):
        check_valid()
        if offset < 0 or offset >= self.size:
            raise IndexError
        return self.get_byte(self.original_buffers, offset)

    def get_modified_bytes(self, offset, b):
        return self.get_bytes(self.layered_buffers, offset, b, 0, len(b))

    def get_original_bytes(self, offset, b):
        return self.get_bytes(self.original_buffers, offset, b, 0, len(b))

    def put_byte(self, offset, byte):
        check_valid()
        if offset < 0 or offset >= self.size:
            raise IndexError
        # The max buffer size will be the size of the first buffer.
        max_buffer_size = self.layered_buffers[0].length
        db_buffer_index = (offset // max_buffer_size)
        local_offset = (offset % max_buffer_size)
        self.layered_buffers[db_buffer_index].put_byte(local_offset, byte)

    def put_bytes(self, offset, b):
        return self.put_bytes(offset, b, 0, len(b))

    def get_byte(self, buffers, offset):
        check_valid()
        if offset < 0 or offset >= self.size:
            raise IndexError
        # The max buffer size will be the size of the first buffer.
        max_buffer_size = buffers[0].length
        db_buffer_index = (offset // max_buffer_size)
        local_offset = (offset % max_buffer_size)
        return buffers[db_buffer_index].get_byte(local_offset)

    def get_bytes(self, buffers, offset, b, off, length):
        check_valid()
        if off < 0 or length < 0 or length > len(b) - off:
            raise IndexError
        # adjust size if asking length is more than we have
        length = min(length, self.size - offset)
        if length == 0:
            return 0

        max_buffer_size = buffers[0].length
        file_bytes_offset = offset
        byteArrayOffset = off
        n = length

        while n > 0:
            db_buffer_index = (file_bytes_offset // max_buffer_size)
            local_offset = (file_bytes_offset % max_buffer_size)
            read_len = min(max_buffer_size - local_offset, n)
            buffers[db_buffer_index].get(local_offset, b, byteArrayOffset, read_len)
            n -= read_len
            file_bytes_offset += read_len
            byteArrayOffset += read_len

        return length

    def check_valid(self):
        if self.invalid:
            raise ConcurrentModificationException()

    def invalidate(self):
        self.invalid = True

    def __str__(self):
        return self.filename

    def __hash__(self):
        return (id ^ (id >> 32))

    def __eq__(self, other):
        if self is other:
            return True
        if other is None:
            return False
        if type(self) != type(other):
            return False
        adapter = self.adapter
        id = self.id
        invalid = self.invalid

        if (adapter != other.adapter or 
            id != other.id or 
            invalid != other.invalid):
            return False
        return True
