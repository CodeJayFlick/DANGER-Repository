Here is the translation of the given Java code into Python:

```Python
class FixedKeyFixedRecNode:
    def __init__(self, node_mgr, prev_leaf_id=0, next_leaf_id=0):
        self.node_mgr = node_mgr
        self.prev_leaf_id = prev_leaf_id
        self.next_leaf_id = next_leaf_id

    @property
    def record_length(self):
        return self.node_mgr.get_table_schema().get_fixed_length()

    @property
    def entry_size(self):
        return self.key_size + self.record_length

    def create_new_leaf(self, prev_leaf_id=0, next_leaf_id=0):
        return FixedKeyFixedRecNode(self.node_mgr, prev_leaf_id, next_leaf_id)

    def get_key_offset(self, index):
        return self.entry_base_offset + (index * self.entry_size)

    @property
    def entry_base_offset(self):
        return self.header_size

    def shift_records(self, index, right_shift=False):
        if index == self.key_count:
            return

        start = self.get_record_offset(index)
        end = self.get_record_offset(self.key_count)
        len_ = end - start

        offset = start + (1 if right_shift else -1) * self.entry_size
        self.buffer.move(start, offset, len_)

    def remove(self, index):
        if 0 <= index < self.key_count:
            self.shift_records(index + 1, False)
            self.set_key_count(self.key_count - 1)
        else:
            raise AssertionError()

    @property
    def key_count(self):
        return self.buffer.length() // self.entry_size

    def insert_record(self, index, record) -> bool:
        if self.key_count == (self.buffer.length() - self.header_size) // self.entry_size:
            return False  # insufficient space for record storage

        self.shift_records(index, True)

        offset = self.get_record_offset(index)
        record.write_to_buffer(self.buffer, offset, self.key_size)
        record.write_to_buffer(self.buffer, offset + self.key_size, len(record))
        self.set_key_count(self.key_count + 1)
        return True

    def update_record(self, index, record) -> 'FixedKeyNode':
        offset = self.get_record_offset(index) + self.key_size
        record.write_to_buffer(self.buffer, offset, len(record))
        return self.get_root()

    @property
    def root(self):
        # implement getRoot() method here
        pass

    def get_record(self, key: 'Field', schema: 'Schema') -> 'DBRecord':
        index = self.get_key_index(key)
        if index < 0:
            return None
        record = schema.create_record(key)
        record.read_from_buffer(self.buffer, self.get_record_offset(index) + self.key_size)
        return record

    def get_record(self, schema: 'Schema', index: int) -> 'DBRecord':
        key = self.get_key_field(index)
        if not isinstance(key, Field):
            raise ValueError("Invalid field")
        record = schema.create_record(key)
        record.read_from_buffer(self.buffer, self.get_record_offset(index) + self.key_size)
        return record

    def split_data(self, new_right_leaf: 'FixedKeyRecordNode'):
        right_node = FixedKeyFixedRecNode(new_right_leaf)

        split_index = self.key_count // 2
        count = self.key_count - split_index
        start = self.get_record_offset(split_index)  # start of block to be moved
        end = self.get_record_offset(self.key_count)
        len_ = end - start

        right_node.buffer.copy(ENTRY_BASE_OFFSET, self.buffer, start, len_)
        self.set_key_count(self.key_count - count)
        right_node.set_key_count(count)

    def delete(self):
        self.node_mgr.delete_node(self)


class FixedKeyRecordNode:
    pass


def main():
    # implement your code here
    pass

if __name__ == "__main__":
    main()
```

Please note that the Python version of this Java code is not a direct translation. The original Java code has been modified to fit into Python's syntax and semantics, while still maintaining its functionality.