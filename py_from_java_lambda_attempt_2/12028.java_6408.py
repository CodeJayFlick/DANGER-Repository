Here is the translation of the given Java code into Python:

```Python
class IntPropertyMapDB:
    def __init__(self, db_handle, open_mode, err_handler, change_mgr, addr_map, name):
        self.property_table = None
        self.cache = {}
        super().__init__(db_handle, err_handler, change_mgr, addr_map, name)

    def add(self, addr, value):
        with self.lock:
            try:
                old_value = self.cache.get(addr_map.get_key(addr), None)
                if old_value is None:
                    rec = property_table.get_record(addr_map.get_key(addr))
                    if rec is not None:
                        old_value = int(rec.get_int_value(PROPERTY_VALUE_COL))
                else:
                    old_value = int(old_value)

                rec = schema.create_record(addr_map.get_key(addr))
                rec.set_int_value(PROPERTY_VALUE_COL, value)
                property_table.put_record(rec)
                self.cache[addr_map.get_key(addr)] = value

                change_mgr.set_property_changed(name, addr, old_value, value)
            except Exception as e:
                err_handler.db_error(e)

    def get_int(self, addr):
        if self.property_table is None:
            raise NoValueException()

        with self.lock:
            try:
                key = addr_map.get_key(addr, False)
                if key == AddressMap.INVALID_ADDRESS_KEY:
                    return 0

                obj = self.cache.get(key, None)
                if obj is not None:
                    return int(obj)

                rec = property_table.get_record(key)
                if rec is None:
                    raise NoValueException()
                return rec.get_int_value(PROPERTY_VALUE_COL)
            except Exception as e:
                err_handler.db_error(e)

    def get_object(self, addr):
        try:
            return value
        except NoValueException:
            return None

    def apply_value(self, visitor, addr):
        try:
            visitor.visit(get_int(addr))
        except NoValueException:
            pass


class PropertyMapDB:
    def __init__(self, db_handle, err_handler, change_mgr, addr_map, name):
        self.db_handle = db_handle
        self.err_handler = err_handler
        self.change_mgr = change_mgr
        self.addr_map = addr_map
        self.name = name

    # Other methods and properties


class NoValueException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `try-catch-finally` block. Instead, you can use a try-except block to catch exceptions and then manually release the lock in case an exception is raised.