Here is the equivalent Python code:

```Python
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
```

Note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the concept of a class having its own package is different in Python and Java. In Python, you can put all your classes into one file or separate them into multiple files based on their functionality.

In this code:

- The `StorageGroupMNode` class has been defined with an initializer method (`__init__`) that takes three parameters: parent (default None), name (default None) and data_ttl (default 0).
- Properties have been used to implement getter and setter methods for the `data_ttl`.
- A property is a way of implementing getters and setters in Python. The syntax is similar to Java's.
- The `is_storage_group` method returns True, indicating that this node represents a storage group.
- The `serialize_to` method serializes the StorageGroupMNode by calling its own serialize_children method and then log_writer.serialize_storage_group_mnode(self).
- Two static methods have been defined: one to deserialize from an MLogWriter plan and another to deserialize from a list of node information.