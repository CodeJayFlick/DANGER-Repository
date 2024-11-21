class ShowTTLPlan:
    def __init__(self, storage_groups):
        self.storage_groups = storage_groups
        super().__init__("TTL")

    @property
    def paths(self):
        return None  # equivalent to getPaths() returning null

    @property
    def storage_groups(self):
        return self._storage_groups
