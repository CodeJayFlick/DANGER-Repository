class StorageGroupMNode:
    def __init__(self, parent=None, name: str = None, data_ttl: int = 0):
        self.parent = parent
        self.name = name
        self.data_ttl = data_ttl

    @property
    def data_ttl(self) -> int:
        return self._data_ttl

    @data_ttl.setter
    def data_ttl(self, value: int):
        self._data_ttl = value

    def is_storage_group(self) -> bool:
        return True

    def serialize_to(self, log_writer):
        self.serialize_children(log_writer)
        log_writer.serialize_storage_group_mnode(self)

    @staticmethod
    def deserialize_from(plan):
        return StorageGroupMNode(None, plan.name, plan.data_ttl)

    @staticmethod
    def deserialize_from(node_info: list) -> 'StorageGroupMNode':
        name = node_info[1]
        data_ttl = int(node_info[2])
        return StorageGroupMNode(None, name, data_ttl)
