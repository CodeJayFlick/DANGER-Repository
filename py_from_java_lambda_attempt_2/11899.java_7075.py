Here is the translation of the given Java code into Python:

```Python
class ParentChildDBAdapterV0:
    VERSION = 0
    PARENT_COL = 0
    CHILD_COL = 1
    
    V0_SCHEMA = {
        "KEY": {"fields": [{"name": "Parent ID", "type": int}, {"name": "Child ID", "type": int}],
                "description": "Schema for version 0"}
    
    def __init__(self, handle, create=False):
        if create:
            self.table = handle.create_table("TABLE_NAME", V0_SCHEMA)
        else:
            try:
                self.table = handle.get_table("TABLE_NAME")
                if not self.table:
                    raise VersionException(True)
                if self.table.schema["version"] != VERSION:
                    raise VersionException(f"Expected version {VERSION} for table 'TABLE_NAME' but got {self.table.schema['version']}")
            except (VersionException, KeyError):
                pass
    
    def create_record(self, parent_id: int, child_id: int) -> None:
        key = self.table.key
        record = {"Parent ID": parent_id, "Child ID": child_id}
        self.table.put_record(record)
    
    def remove_record(self, parent_id: int, child_id: int) -> None:
        try:
            for id in self.table.find_records({"Child ID": child_id}):
                if self.table.get_record(id)["Parent ID"] == parent_id:
                    self.table.delete_record(id)
                    return
        except KeyError:
            pass
    
    def get_parent_ids(self, child_id: int) -> list[int]:
        try:
            ids = [id for id in self.table.find_records({"Child ID": child_id})]
            return [self.table.get_record(id)["Parent ID"] for id in ids]
        except KeyError:
            return []
    
    @property
    def needs_initializing(self):
        return self._needs_initializing
    
    @needs_initializing.setter
    def set_needs_initializing(self, value: bool) -> None:
        self._needs_initializing = value

class VersionException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `throws` keyword. The exceptions are raised using the built-in exception mechanism in Python.