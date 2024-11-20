class LongKeyRecordNode:
    def __init__(self):
        pass  # abstract class cannot be instantiated directly

    @staticmethod
    def ID_SIZE():
        return 4

    @staticmethod
    def PREV_LEAF_ID_OFFSET():
        return LongKeyRecordNode.ID_SIZE()

    @staticmethod
    def NEXT_LEAF_ID_OFFSET():
        return LongKeyRecordNode.PREV_LEAF_ID_OFFSET() + LongKeyRecordNode.ID_SIZE()

    @staticmethod
    def RECORD_LEAF_HEADER_SIZE():
        return LongKeyRecordNode.LONGKEY_NODE_HEADER_SIZE() + 2 * LongKeyRecordNode.ID_SIZE

    def __init__(self, node_mgr, buffer):
        pass  # abstract class cannot be instantiated directly

    def __init__(self, node_mgr, node_type, prev_leaf_id, next_leaf_id):
        pass  # abstract class cannot be instantiated directly

    @staticmethod
    def get_buffer(self):
        return self.buffer

    @staticmethod
    def put_int(self, offset, value):
        if isinstance(self.get_buffer(), bytes):
            self.get_buffer()[offset:offset+4] = struct.pack('>I', value)
        else:
            raise ValueError("Buffer is not a byte array")

    @staticmethod
    def get_parent(self):
        return self.parent

    @staticmethod
    def set_parent(self, parent):
        self.parent = parent

    @staticmethod
    def log_consistency_error(self, table_name, msg, t=None):
        if t:
            print(f"Consistency Error ({table_name}): {msg}")
            print(f"  bufferID={self.get_buffer_id()} key[0]=0x{LongKeyRecordNode.to_hex(LongKeyRecordNode.get_key(0))}")
            raise t
        else:
            print(f"Consistency Error ({table_name}): {msg}")
            print(f"  bufferID={self.get_buffer_id()} key[0]=0x{LongKeyRecordNode.to_hex(LongKeyRecordNode.get_key(0))}")

    @staticmethod
    def is_consistent(self, table_name):
        consistent = True
        prev_key = 0
        for i in range(len(self.keys)):
            if i != 0:
                key = self.get_key(i)
                if key <= prev_key:
                    consistent = False
                    self.log_consistency_error(table_name, f"key[{i}] <= key[{i-1}]", None)
                    print(f"  key[{i}].minKey=0x{LongKeyRecordNode.to_hex(key)}")
                    print(f"  key[{i-1}].minKey=0x{LongKeyRecordNode.to_hex(prev_key)}")
            prev_key = key
        if self.get_parent() and not self.is_leftmost_key(self.get_key(0)):
            consistent = False
            self.log_consistency_error(table_name, "previous-leaf should not exist", None)
        node = self.get_next_leaf()
        if node:
            if self.get_parent() and not self.is_rightmost_key(self.get_key(0)):
                consistent = False
                self.log_consistency_error(table_name, "next-leaf should not exist", None)
            else:
                me = node.get_previous_leaf()
                if me != self:
                    consistent = False
                    self.log_consistency_error(table_name, "next-leaf is not linked to this leaf", None)
        return consistent

    @staticmethod
    def get_leaf_node(self, key):
        return self

    @staticmethod
    def get_next_leaf(self):
        if isinstance(self.get_buffer(), bytes) and 0 <= int.from_bytes(self.get_buffer()[LongKeyRecordNode.NEXT_LEAF_ID_OFFSET():], 'big'):
            node = LongKeyRecordNode(node_mgr=self.node_mgr, buffer=bytes(int.from_bytes(self.get_buffer()[LongKeyRecordNode.NEXT_LEAF_ID_OFFSET():], 'big')))
        else:
            return None
        return node

    @staticmethod
    def get_previous_leaf(self):
        if isinstance(self.get_buffer(), bytes) and 0 <= int.from_bytes(self.get_buffer()[LongKeyRecordNode.PREV_LEAF_ID_OFFSET():], 'big'):
            node = LongKeyRecordNode(node_mgr=self.node_mgr, buffer=bytes(int.from_bytes(self.get_buffer()[LongKeyRecordNode.PREV_LEAF_ID_OFFSET():], 'big')))
        else:
            return None
        return node

    @staticmethod
    def get_key_index(self, key):
        min = 0
        max = len(self.keys) - 1
        while min <= max:
            i = (min + max) // 2
            k = self.get_key(i)
            if k == key:
                return i
            elif k < key:
                min = i + 1
            else:
                max = i - 1
        return -(min + 1)

    @staticmethod
    def get_root(self):
        pass

    @staticmethod
    to_hex(key):
        if isinstance(key, int) or isinstance(key, long):
            return hex(key)[2:]
        elif isinstance(key, bytes):
            return ''.join(f"{i:02x}" for i in key)
        else:
            raise ValueError("Invalid type")

class LongKeyInteriorNode(LongKeyRecordNode):

    def __init__(self, node_mgr, node_type, prev_leaf_id, next_leaf_id):
        super().__init__(node_mgr=node_mgr, buffer=bytes(), node_type=node_type, prev_leaf_id=prev_leaf_id, next_leaf_id=next_leaf_id)

class LongKeyFixedRecNode(LongKeyRecordNode):

    def __init__(self, node_mgr, fixed_length, prev_leaf_id, next_leaf_id):
        super().__init__(node_mgr=node_mgr, buffer=bytes(), fixed_length=fixed_length, prev_leaf_id=prev_leaf_id, next_leaf_id=next_leaf_id)

class LongKeyVarRecNode(LongKeyRecordNode):

    def __init__(self, node_mgr, var_length, prev_leaf_id, next_leaf_id):
        super().__init__(node_mgr=node_mgr, buffer=bytes(), var_length=var_length, prev_leaf_id=prev_leaf_id, next_leaf_id=next_leaf_id)

class NodeMgr:

    pass

class TableSchema:

    def __init__(self, fixed_length=None, variable_length=False):
        self.fixed_length = fixed_length
        self.variable_length = variable_length

class DBRecord:

    def __init__(self, key, schema):
        self.key = key
        self.schema = schema

if __name__ == "__main__":
    node_mgr = NodeMgr()
    table_schema = TableSchema(fixed_length=4)
    db_record = DBRecord(0x1234567890123456L, table_schema)

