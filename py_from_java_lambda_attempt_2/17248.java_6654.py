Here is the translation of the Java code to Python:
```
class DeletePartitionOperator:
    def __init__(self):
        self.storage_group_name = None
        self.partition_ids = set()

    @property
    def storage_group_name(self):
        return self._storage_group_name

    @storage_group_name.setter
    def storage_group_name(self, value):
        self._storage_group_name = value

    @property
    def partition_ids(self):
        return self._partition_ids

    @partition_ids.setter
    def partition_ids(self, value):
        self._partition_ids = set(value)

    def generate_physical_plan(self, generator):
        if not self.storage_group_name or not self.partition_ids:
            raise ValueError("Storage group name and partition IDs must be specified")
        return DeletePartitionPlan(self.storage_group_name, self.partition_ids)
```
Note that I've used Python's built-in `set` type to represent the set of partition IDs. In Java, you would need to use a specific implementation like `HashSet<Long>`.

I've also replaced the `OperatorType.DELETE_PARTITION` constant with nothing, as it seems unnecessary in this translation. If you want to keep track of operator types, you could add an enumeration or a string constant instead.

The rest of the code is straightforward: I've translated each method one-to-one from Java to Python, using equivalent syntax and semantics where possible.