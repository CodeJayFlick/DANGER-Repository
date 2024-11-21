Here is the translation of the given Java code into equivalent Python:

```Python
class ParentChildAdapter:
    TABLE_NAME = "DT_PARENT_CHILD"

    @staticmethod
    def get_adapter(handle, open_mode):
        if open_mode == 'CREATE':
            return ParentChildDBAdapterV0(handle, True)
        try:
            return ParentChildDBAdapterV0(handle, False)
        except Exception as e:
            if not isinstance(e, VersionException) or open_mode == 'UPDATE':
                raise
            read_only_adapter = ParentChildAdapter.find_readonly_adapter(handle)
            if open_mode == 'UPGRADE':
                adapter = ParentChildAdapter.upgrade(handle, read_only_adapter)
            return adapter

    @staticmethod
    def find_readonly_adapter(handle):
        return ParentChildDBAdapterNoTable(handle)

    @staticmethod
    def upgrade(handle, old_adapter):
        try:
            new_adapter = ParentChildDBAdapterV0(handle, True)
            new_adapter.set_needs_initializing()
            return new_adapter
        except Exception as e:
            raise

    def needs_initializing(self):
        pass  # Abstract method in Python; must be implemented by subclasses.

    def create_record(self, parent_id, child_id):  # abstract method
        pass

    def remove_record(self, parent_id, child_id):  # abstract method
        pass

    def get_parent_ids(self, child_id):  # abstract method
        pass

    def remove_all_records_for_parent(self, parent_id):  # abstract method
        pass

    def remove_all_records_for_child(self, child_id):  # abstract method
        pass


class ParentChildDBAdapterV0:
    def __init__(self, handle, needs_initializing):
        self.handle = handle
        self.needs_initializing = needs_initializing

    def set_needs_initializing(self):
        self.needs_initializing = True


class ParentChildDBAdapterNoTable:
    def __init__(self, handle):
        self.handle = handle
```

Note that the `IOException` and `VersionException` classes are not available in Python. You would need to define your own exceptions or use built-in ones like `Exception`.