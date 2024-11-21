Here is the translation of the given Java code into Python:

```Python
class VoidPropertyMapDB:
    VOID_OBJECT = object()

    def __init__(self, db_handle, open_mode, err_handler, change_mgr, addr_map, name):
        super().__init__()
        self.db_handle = db_handle
        self.open_mode = open_mode
        self.err_handler = err_handler
        self.change_mgr = change_mgr
        self.addr_map = addr_map
        self.name = name

    def add(self, addr):
        with self.lock:
            key = self.addr_map.get_key(addr, True)
            old_value = bool(self.has_property(addr))

            if not hasattr(self, 'property_table'):
                self.create_table()
            rec = self.schema.create_record(key)
            self.property_table.put_record(rec)
            self.cache.put(key, self.VOID_OBJECT)
            self.change_mgr.set_property_changed(self.name, addr, old_value, True)

    def apply_value(self, visitor, addr):
        if self.has_property(addr):
            visitor.visit()

    def get_object(self, addr):
        if self.has_property(addr):
            return True
        return None

class PropertyMapDB:
    pass  # This class is not implemented in the given Java code.

# Usage example:

db_handle = ...  # Initialize database handle
open_mode = ...
err_handler = ...  # Initialize error handler
change_mgr = ...  # Initialize change manager
addr_map = ...  # Initialize address map
name = ...

property_map_db = VoidPropertyMapDB(db_handle, open_mode, err_handler, change_mgr, addr_map, name)

# Use the property map database as needed.
```

Please note that this translation is not a direct conversion from Java to Python. The given code has been modified and simplified for better readability in Python.