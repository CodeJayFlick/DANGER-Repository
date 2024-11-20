class VarKeyNode:
    KEY_TYPE_SIZE = 1
    KEY_COUNT_SIZE = 4

    def __init__(self, node_mgr: 'NodeMgr', buf: DataBuffer):
        self.node_mgr = node_mgr
        self.buffer = buf
        self.key_type = Field(buf.get_byte(VarKeyNode.KEY_TYPE_OFFSET))
        self.key_count = buf.get_int(VarKeyNode.KEY_COUNT_OFFSET)
        self.max_key_length = VarKeyInteriorNode.get_max_key_length(len(buf))
        self.node_mgr.add_node(self)

    def __init__(self, node_mgr: 'NodeMgr', node_type: int, key_type: Field):
        self.node_mgr = node_mgr
        self.buffer = node_mgr.get_buffer_mgr().create_buffer()
        NodeMgr.set_node_type(self.buffer, node_type)
        self.key_type = key_type.new_field()
        self.buffer.put_byte(VarKeyNode.KEY_TYPE_OFFSET, key_type.field_type())
        self.set_key_count(0)
        self.max_key_length = VarKeyInteriorNode.get_max_key_length(len(buf))
        self.node_mgr.add_node(self)

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def set_parent(self, value: 'VarKeyInteriorNode'):
        if not isinstance(value, VarKeyInteriorNode):
            raise TypeError("Parent must be a VarKeyInteriorNode")
        self._parent = value

    @property
    def buffer_id(self):
        return self.buffer.id()

    @property
    def buffer(self):
        return self._buffer

    @buffer.setter
    def set_buffer(self, value: DataBuffer):
        if not isinstance(value, DataBuffer):
            raise TypeError("Buffer must be a DataBuffer")
        self._buffer = value

    def get_root(self) -> 'VarKeyInteriorNode':
        if self.parent is None:
            return self
        else:
            return self.parent.get_root()

    @property
    def key_count(self):
        return self._key_count

    @key_count.setter
    def set_key_count(self, value: int):
        self._key_count = value
        self.buffer.put_int(VarKeyNode.KEY_COUNT_OFFSET, value)

    def compare_key_field(self, k: Field, index: int) -> int:
        return k.compare(self.buffer.get_slice(0, VarKeyInteriorNode.MAX_KEY_LENGTH), 0)

    @abstractmethod
    def get_key_offset(self, index: int):
        pass

    @abstractmethod
    def get_key_field(self, index: int) -> Field:
        pass

    @abstractmethod
    def get_leaf_node(self, key: Field) -> 'VarKeyRecordNode':
        pass

    @abstractmethod
    def get_leftmost_leaf_node(self) -> 'VarKeyRecordNode':
        pass

    @abstractmethod
    def get_rightmost_leaf_node(self) -> 'VarKeyRecordNode':
        pass


class VarKeyInteriorNode:
    MAX_KEY_LENGTH = 0

    @staticmethod
    def get_max_key_length(length: int):
        return length
