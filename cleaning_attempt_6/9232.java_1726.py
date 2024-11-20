class LongKeyNode:
    KEY_COUNT_SIZE = 4
    KEY_COUNT_OFFSET = NodeMgr.NODE_HEADER_SIZE + KEY_COUNT_SIZE
    LONGKEY_NODE_HEADER_SIZE = NodeMgr.NODE_HEADER_SIZE + KEY_COUNT_SIZE

    def __init__(self, node_mgr: 'NodeMgr', buffer: 'DataBuffer'):
        self.node_mgr = node_mgr
        self.buffer = buffer
        self.key_count = buffer.get_int(KEY_COUNT_OFFSET)
        self.node_mgr.add_node(self)

    @classmethod
    def create_new(cls, node_mgr: 'NodeMgr', node_type: bytes) -> None:
        try:
            buffer = node_mgr.get_buffer_mgr().create_buffer()
            NodeMgr.set_node_type(buffer, node_type)
            cls.__init__(self=None, node_mgr=node_mgr, buffer=buffer)

    @property
    def buffer_id(self):
        return self.buffer.id

    @property
    def buffer(self):
        return self._buffer

    @buffer.setter
    def buffer(self, value: 'DataBuffer'):
        self._buffer = value

    @classmethod
    def get_root(cls) -> 'LongKeyNode':
        if cls.parent is not None:
            return cls.parent.get_root()
        return this

    @property
    def key_count(self):
        return self._key_count

    @key_count.setter
    def key_count(self, value: int):
        self._key_count = value
        buffer.put_int(KEY_COUNT_OFFSET, value)

    def get_key(self, index: int) -> int:
        raise NotImplementedError("get_key must be implemented by subclass")

    def get_field(self, index: int) -> 'Field':
        return LongField(self.get_key(index))

    @classmethod
    def get_leaf_node(cls, key: int) -> 'LongKeyRecordNode':
        raise NotImplementedError("get_leaf_node must be implemented by subclass")
