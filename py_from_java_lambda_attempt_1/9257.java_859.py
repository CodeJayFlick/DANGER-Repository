Here is the translation of the Java code into Python:

```Python
class VarRecNode:
    def __init__(self, node_mgr, prev_leaf_id=0, next_leaf_id=0):
        self.node_mgr = node_mgr
        self.prev_leaf_id = prev_leaf_id
        self.next_leaf_id = next_leaf_id

    @property
    def header_size(self):
        return RECORD_LEAF_HEADER_SIZE

    @property
    def key_size(self):
        return 8

    @property
    def offset_size(self):
        return 4

    @property
    def indirect_option_size(self):
        return 1

    @property
    def entry_size(self):
        return self.key_size + self.offset_size + self.indirect_option_size

    @property
    def key_base_offset(self):
        return self.header_size

    @property
    def data_offset_base_offset(self):
        return self.key_base_offset + self.key_size

    @property
    def ind_option_base_offset(self):
        return self.data_offset_base_offset + self.offset_size

    def __init__(self, node_mgr, buf):
        super().__init__(node_mgr, buf)

    def get_key(self, index):
        return buf.get_long(get_key_offset(index))

    def get_key_offset(self, index):
        return self.key_base_offset + (index * self.entry_size)

    def get_record_data_offset(self, index):
        return buf.get_int(self.data_offset_base_offset + (index * self.entry_size))

    def put_record_data_offset(self, index, offset):
        buf.put_int(self.data_offset_base_offset + (index * self.entry_size), offset)

    def has_indirect_storage(self, index):
        return buf.get_byte(self.ind_option_base_offset + (index * self.entry_size)) != 0

    def enable_indirect_storage(self, index, state):
        buf.put_byte(self.ind_option_base_offset + (index * self.entry_size), state and 1 or 0)

    def get_free_space(self):
        return key_count == 0 and len(buf) or get_record_data_offset(key_count - 1) - (key_count * self.entry_size) - RECORD_LEAF_HEADER_SIZE

    def get_record_length(self, index):
        if index == 0:
            return len(buf) - get_record_data_offset(0)
        else:
            return get_record_data_offset(index - 1) - get_record_data_offset(index)

    def move_records(self, index, offset):
        start = get_record_data_offset(key_count - 1)
        end = get_record_data_offset(index - 1)
        len = end - start
        buf.move(start, start + offset, len)
        for i in range(index):
            put_record_data_offset(i, get_record_data_offset(i) + offset)
        return end + offset

    def get_record(self, schema, index):
        key = self.get_key(index)
        record = schema.create_record(key)
        if has_indirect_storage(index):
            buf_id = buf.get_int(get_record_data_offset(index))
            chained_buffer = ChainedBuffer(node_mgr.get_buffer_mgr(), buf_id)
            record.read(chained_buffer, 0)
        else:
            record.read(buf, get_record_data_offset(index))
        return record

    def get_record_offset(self, index):
        if has_indirect_storage(index):
            return -buf.get_int(get_record_data_offset(index))
        else:
            return self.get_record_data_offset(index)

    def split_data(self, new_right_leaf):
        right_node = VarRecNode(node_mgr)
        split_index = self.get_split_index()
        count = key_count - split_index
        start = get_record_data_offset(key_count - 1)	# start of block to be moved
        end = get_record_data_offset(split_index - 1)   # end of block to be moved
        len = end - start					# length of block to be moved
        right_offset = len + buffer.length()     # data offset within new leaf node 

        buf.copy(right_node.buffer, right_offset, self.buffer, start, len)
        right_node.buffer.copy(self.buffer, KEY_BASE_OFFSET, self.buffer, KEY_BASE_OFFSET + (split_index * ENTRY_SIZE), count * ENTRY_SIZE)

        for i in range(count):
            put_record_data_offset(i, get_record_data_offset(i) - offsetCorrection)
        set_key_count(key_count - count)
        right_node.set_key_count(count)

    def update_record(self, index, record):
        if has_indirect_storage(index):
            len = 4
        else:
            len = record.length()
        maxRecordLength = (len(buf) - RECORD_LEAF_HEADER_SIZE) >> 2 - ENTRY_SIZE	# min 4 records per node
        useIndirect = len > maxRecordLength

        if useIndirect and has_indirect_storage(index):
            return self.update_record(index, record)

        offsetCorrection = oldLen - len
        buf.move(start + offsetCorrection, start, len)
        put_record_data_offset(index, get_record_data_offset(index) + offsetCorrection)

    def insert_record(self, index, record):
        if has_indirect_storage(index):
            return False	# insufficient space for record storage

        make_room_for_new_key = True
        while (make_room_for_new_key and len > 0):
            buf.move(start - ENTRY_SIZE, start, len)
            put_record_data_offset(index, get_record_data_offset(index) + offsetCorrection)

    def remove(self, index):
        if has_indirect_storage(index):
            buffer_id = self.buffer.get_int(get_record_data_offset(index))
            chained_buffer = ChainedBuffer(node_mgr.get_buffer_mgr(), buffer_id)
            chained_buffer.delete()
            buf.put_int(offset, -1)
        else:
            offsetCorrection = oldLen - len
            move_records(index + 1, len)

    def delete(self):
        for i in range(key_count):
            if has_indirect_storage(i):
                offset = get_record_data_offset(i)
                buffer_id = self.buffer.get_int(offset)
                chained_buffer = ChainedBuffer(node_mgr.get_buffer_mgr(), buffer_id)
                chained_buffer.delete()
                buf.put_int(offset, -1)

        node_mgr.delete_node(self)