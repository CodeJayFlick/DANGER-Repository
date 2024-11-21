class NodeMgr:
    NODE_TYPE_SIZE = 1
    NODE_TYPE_OFFSET = 0
    NODE_HEADER_SIZE = NODE_TYPE_SIZE

    LONGKEY_INTERIOR_NODE = 0
    LONGKEY_VAR_REC_NODE = 1
    LONGKEY_FIXED_REC_NODE = 2
    VARKEY_INTERIOR_NODE = 3
    VARKEY_REC_NODE = 4
    FIXEDKEY_INTERIOR_NODE = 5
    FIXEDKEY_VAR_REC_NODE = 6
    FIXEDKEY_FIXED_REC_NODE = 7
    CHAINED_BUFFER_INDEX_NODE = 8
    CHAINED_BUFFER_DATA_NODE = 9

    def __init__(self, table, buffer_mgr):
        self.buffer_mgr = buffer_mgr
        self.schema = table.get_schema()
        self.table_name = table.name
        self.leaf_record_cnt = 0
        self.node_table = {}

    def get_buffer_mgr(self):
        return self.buffer_mgr

    def get_schema(self):
        return self.schema

    def get_table_name(self):
        return self.table_name

    def release_nodes(self):
        for node in list(self.node_table.values()):
            if isinstance(node, RecordNode):
                self.leaf_record_cnt -= node.key_count
            self.buffer_mgr.release_buffer(node.get_buffer())
        self.node_table = {}
        result = -self.leaf_record_cnt
        self.leaf_record_cnt = 0
        return result

    def release_read_only_node(self, buffer_id):
        if buffer_id in self.node_table:
            node = self.node_table[buffer_id]
            if isinstance(node.get_buffer(), DataBuffer) and not node.get_buffer().is_dirty():
                if isinstance(node, RecordNode):
                    self.leaf_record_cnt -= node.key_count
                self.buffer_mgr.release_buffer(node.get_buffer())
                del self.node_table[buffer_id]

    def add_node(self, node):
        self.node_table[node.get_buffer_id()] = node

    def delete_node(self, buffer_id):
        if buffer_id in self.node_table:
            node = self.node_table.pop(buffer_id)
            self.buffer_mgr.release_buffer(node.get_buffer())
            self.buffer_mgr.delete_buffer(buffer_id)

    @staticmethod
    def is_var_key_node(buffer_mgr, buffer_id):
        buf = buffer_mgr.get_buffer(buffer_id)
        try:
            if get_node_type(buf) in [NodeMgr.VARKEY_REC_NODE, NodeMgr.VARKEY_INTERIOR_NODE]:
                return True
        finally:
            buffer_mgr.release_buffer(buf)

    def get_long_key_node(self, buffer_id):
        node = self.node_table.get(buffer_id)
        if node is not None:
            return node

        buf = self.buffer_mgr.get_buffer(buffer_id)
        node_type = get_node_type(buf)
        if node_type == NodeMgr.LONGKEY_VAR_REC_NODE:
            node = VarRecNode(self, buf)
            self.leaf_record_cnt += node.key_count
        elif node_type == NodeMgr.LONGKEY_FIXED_REC_NODE:
            node = FixedRecNode(self, buf, self.schema.get_fixed_length())
            self.leaf_record_cnt += node.key_count
        elif node_type == NodeMgr.LONGKEY_INTERIOR_NODE:
            node = LongKeyInteriorNode(self, buf)
        else:
            buffer_mgr.release_buffer(buf)
            raise AssertionError("Unexpected Node Type found")

        return node

    def get_fixed_key_node(self, buffer_id):
        node = self.node_table.get(buffer_id)
        if node is not None:
            return node

        buf = self.buffer_mgr.get_buffer(buffer_id)
        node_type = get_node_type(buf)
        if node_type == NodeMgr.FIXEDKEY_VAR_REC_NODE:
            node = FixedKeyVarRecNode(self, buf)
            self.leaf_record_cnt += node.key_count
        elif node_type == NodeMgr.FIXEDKEY_FIXED_REC_NODE:
            node = FixedKeyFixedRecNode(self, buf)
            self.leaf_record_cnt += node.key_count
        elif node_type == NodeMgr.FIXEDKEY_INTERIOR_NODE:
            node = FixedKeyInteriorNode(self, buf)
        else:
            buffer_mgr.release_buffer(buf)
            raise AssertionError("Unexpected Node Type found")

        return node

    def get_var_key_node(self, buffer_id):
        node = self.node_table.get(buffer_id)
        if node is not None:
            return node

        buf = self.buffer_mgr.get_buffer(buffer_id)
        node_type = get_node_type(buf)
        if node_type == NodeMgr.VARKEY_REC_NODE:
            node = VarKeyRecordNode(self, buf)
            self.leaf_record_cnt += node.key_count
        elif node_type == NodeMgr.VARKEY_INTERIOR_NODE:
            node = VarKeyInteriorNode(self, buf)
        else:
            buffer_mgr.release_buffer(buf)
            raise AssertionError("Unexpected Node Type found")

        return node

    @staticmethod
    def get_node_type(buffer):
        return buffer.get_byte(NodeMgr.NODE_TYPE_OFFSET)

    @staticmethod
    def set_node_type(buffer, node_type):
        buffer.put_byte(NodeMgr.NODE_TYPE_OFFSET, node_type)


class RecordNode:
    pass


class VarRecNode(RecordNode):
    key_count = 0

    def __init__(self, node_mgr, buf):
        self.key_count = get_key_count(buf)
        # Add implementation for VarRecNode here


class FixedRecNode(RecordNode):
    key_count = 0
    fixed_length = None

    def __init__(self, node_mgr, buf, fixed_length):
        self.fixed_length = fixed_length
        self.key_count = get_key_count(buf)
        # Add implementation for FixedRecNode here


def get_key_count(buffer):
    return buffer.get_int(1)


# Usage example:
node_mgr = NodeMgr(table, buffer_mgr)
