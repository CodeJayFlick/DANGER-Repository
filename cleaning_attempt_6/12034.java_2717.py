class StringPropertyMapDB:
    def __init__(self, db_handle, open_mode, err_handler, change_mgr, addr_map, name):
        super().__init__()
        self.check_map_version(open_mode)
        
    def add(self, addr, value):
        with self.lock:
            key = addr_map.get_key(addr, True)

            if property_table is None:
                create_table(StringField.INSTANCE)
            else:
                old_value = cache.get(key)
                if old_value is None:
                    rec = property_table.get_record(key)
                    if rec is not None:
                        old_value = rec.get_string(PROPERTY_VALUE_COL)
            
            rec = schema.create_record(key)
            rec.set_string(PROPERTY_VALUE_COL, value)
            property_table.put_record(rec)
            cache.put(key, value)
            change_mgr.set_property_changed(name, addr, old_value, value)

    def get_string(self, addr):
        if property_table is None:
            return None

        str = None
        with self.lock:
            key = addr_map.get_key(addr, False)
            if key == AddressMap.INVALID_ADDRESS_KEY:
                return None
            str = cache.get(key)
            if str is not None:
                return str
            
            rec = property_table.get_record(key)
            if rec is None:
                return None
            str = rec.get_string(PROPERTY_VALUE_COL)

    def get_object(self, addr):
        return self.get_string(addr)

    def apply_value(self, visitor, addr):
        str = self.get_string(addr)
        if str is not None:
            visitor.visit(str)
