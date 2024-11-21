class DBPropertyMapManager:
    def __init__(self):
        self.property_map_cache = {}

    @staticmethod
    def get_properties_schema():
        return {"Type": "int", "Object Class": "string"}

    def load_property_maps(self, open_mode, monitor=None):
        if open_mode == 0:  # CREATE
            pass

    def find_adapters(self, handle):
        self.properties_db_adapter = PropertiesDBAdapterV0(handle)

    @staticmethod
    def create_int_property_map(db_handle, program, change_mgr, addr_map, property_name):
        return IntPropertyMapDB(db_handle, DBConstants.CREATE, program, change_mgr, addr_map, property_name)

    @staticmethod
    def create_long_property_map(db_handle, program, change_mgr, addr_map, property_name):
        return LongPropertyMapDB(db_handle, DBConstants.CREATE, program, change_mgr, addr_map, property_name)

    @staticmethod
    def create_string_property_map(db_handle, program, change_mgr, addr_map, property_name):
        return StringPropertyMapDB(db_handle, DBConstants.CREATE, program, change_mgr, addr_map, property_name)

    @staticmethod
    def create_object_property_map(db_handle, program, change_mgr, addr_map, property_name, object_class):
        return ObjectPropertyMapDB(db_handle, DBConstants.CREATE, program, change_mgr, addr_map, property_name, object_class)

    @staticmethod
    def create_void_property_map(db_handle, program, change_mgr, addr_map, property_name):
        return VoidPropertyMapDB(db_handle, DBConstants.CREATE, program, change_mgr, addr_map, property_name)

    def get_property_map(self, property_name):
        if self.property_map_cache.get(property_name) is not None:
            return self.property_map_cache[property_name]
        else:
            raise TypeMismatchException("Property " + property_name + " does not exist")

    @staticmethod
    def remove_property_map(db_handle, program, change_mgr, addr_map, property_name):
        if db_handle.contains_key(property_name):
            pm = (db_handle.get(property_name))
            pm.delete()
            db_handle.remove_record(property_name)
            self.property_map_cache.pop(property_name)

    def get_all(self):
        return list(self.property_map_cache.keys())

    @staticmethod
    def remove_range(db_handle, program, change_mgr, addr_map, start_addr, end_addr):
        for property_name in self.get_all():
            pm = (db_handle.get(property_name))
            pm.remove(start_addr, end_addr)

    @staticmethod
    def move_address_range(db_handle, program, change_mgr, addr_map, from_addr, to_addr, length):
        for property_name in self.get_all():
            pm = (db_handle.get(property_name))
            pm.move(from_addr, to_addr, length)

    @staticmethod
    def delete_address_range(db_handle, program, change_mgr, addr_map, start_addr, end_addr):
        remove_range(db_handle, program, change_mgr, addr_map, start_addr, end_addr)
