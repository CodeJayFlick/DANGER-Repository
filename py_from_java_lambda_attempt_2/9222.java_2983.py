Here is the translation of the given Java code into Python:

```Python
class FixedRecNode:
    HEADER_SIZE = RECORD_LEAF_HEADER_SIZE
    ENTRY_BASE_OFFSET = HEADER_SIZE
    KEY_SIZE = 8
    EMPTY_ID_LIST = [0]

    def __init__(self, node_mgr, buf, record_length):
        super().__init__(node_mgr, buf)
        self.record_length = record_length
        self.entry_size = self.KEY_SIZE + self.record_length

    def create_new_leaf(self, prev_leaf_id, next_leaf_id) -> 'FixedRecNode':
        return FixedRecNode(node_mgr, self.record_length, prev_leaf_id, next_leaf_id)

    def get_key(self, index):
        offset = self.get_key_offset(index)
        return buf.getvalue(offset).long()

    def get_key_offset(self, index):
        return self.ENTRY_BASE_OFFSET + (index * self.entry_size)

    def get_record_offset(self, index):
        return self.ENTRY_BASE_OFFSET + (index * self.entry_size)

    def shift_records(self, index: int, right_shift: bool) -> None:
        if index == self.key_count:
            return

        start = self.get_record_offset(index)
        end = self.get_record_offset(self.key_count)
        length = end - start

        offset = start + (1 if right_shift else -1) * self.entry_size
        buf.move(start, offset, length)

    def remove(self, index: int) -> None:
        if 0 <= index < self.key_count:
            self.shift_records(index + 1, False)
            self.set_key_count(self.key_count - 1)

    def insert_record(self, index: int, record: DBRecord) -> bool:
        if self.key_count == (buf.getbuffer().length() - self.HEADER_SIZE) // self.entry_size:
            return False

        self.shift_records(index, True)
        offset = self.get_record_offset(index)
        buf.put_long(offset, record.key())
        record.write(buf, offset + self.KEY_SIZE)
        self.set_key_count(self.key_count + 1)

    def update_record(self, index: int, record: DBRecord) -> 'LongKeyNode':
        offset = self.get_record_offset(index) + self.KEY_SIZE
        record.write(buf, offset)
        return self.get_root()

    def get_record(self, key: long, schema: Schema) -> DBRecord:
        if (index := self.get_key_index(key)) < 0:
            return None

        record = schema.create_record(key)
        record.read(buf, self.get_record_offset(index) + self.KEY_SIZE)

    def split_data(self, new_right_leaf: 'LongKeyNode') -> None:
        right_node = FixedRecNode(new_right_leaf)
        index = self.key_count // 2
        count = self.key_count - index

        start = self.get_record_offset(index)
        end = self.get_record_offset(self.key_count)

        # Copy data to new leaf node
        right_node.buffer.copy(ENTRY_BASE_OFFSET, buf, start, length)

    def delete(self) -> None:
        node_mgr.delete_node(self)

class DBRecord:
    pass

class Schema:
    pass

class NodeMgr:
    LONGKEY_FIXED_REC_NODE = 0
```

Please note that Python does not support direct translation of Java code. It requires a deep understanding of the problem domain and the specific requirements for each part of your program.