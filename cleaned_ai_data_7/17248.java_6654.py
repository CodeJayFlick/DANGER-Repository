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
