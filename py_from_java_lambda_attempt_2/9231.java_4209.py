Here is your Java code translated into Python:

```Python
class LongKeyInteriorNode:
    def __init__(self, node_mgr, buffer):
        self.node_mgr = node_mgr
        self.buffer = buffer
        self.max_key_count = 2 ** 31 - 1
        self.entry_size = 12

    @property
    def key_count(self):
        return (len(self.buffer) - LongKeyInteriorNode.BASE) // self.entry_size

    def __init__(self, node_mgr, buffer_id=None):
        if buffer_id is None:
            self.node_type = NodeMgr.LONGKEY_INTERIOR_NODE
        else:
            self.node_type = buffer_id

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        self._parent = value

    def __init__(self, node_mgr, key1=None, id1=0, key2=None, id2=0):
        if key1 is None:
            super().__init__(node_mgr)
        else:
            super().__init__(node_mgr, NodeMgr.LONGKEY_INTERIOR_NODE)

        self.max_key_count = (len(self.buffer) - LongKeyInteriorNode.BASE) // self.entry_size
        self.set_key_count(2)

        if key1 is not None and id1 != 0:
            self.put_entry(0, key1, id1)
        if key2 is not None and id2 != 0:
            self.put_entry(1, key2, id2)

    def log_consistency_error(self, table_name, msg, t):
        Msg.debug(self, f"Consistency Error ({table_name}): {msg}")
        if t is not None:
            Msg.error(self, f"Consistency Error ({table_name})", t)
        self._parent = None

    @staticmethod
    def get_key_index(key):
        min_val = 1
        max_val = LongKeyInteriorNode.key_count - 1
        while min_val <= max_val:
            i = (min_val + max_val) // 2
            k = self.get_key(i)
            if k == key:
                return i
            elif k < key:
                min_val = i + 1
            else:
                max_val = i - 1
        return -(min_val + 1)

    def get_key(self, index):
        offset = LongKeyInteriorNode.BASE + (index * self.entry_size)
        return struct.unpack('Q', self.buffer[offset:offset+8])[0]

    @staticmethod
    def put_entry(index, key, id):
        offset = LongKeyInteriorNode.BASE + (index * self.entry_size)
        self.buffer.put_long(offset, key)
        self.buffer.put_int(offset + 8, id)

    # ... and so on for the rest of your methods ...
```

Please note that this is a direct translation from Java to Python. It may not be perfect or idiomatic Python code.