class ShowStorageGroupPlan:
    def __init__(self, show_content_type: str, path: 'org.apache.iotdb.db.metadata.PartialPath'):
        self.path = path
        super().__init__(show_content_type)

    @property
    def path(self) -> 'org.apache.iotdb.db.metadata.PartialPath':
        return self._path

# Note: The `PartialPath` class is not a built-in Python type, so you would need to define it separately or use an existing equivalent.
