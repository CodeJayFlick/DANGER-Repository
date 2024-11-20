class ChangeManager:
    DOCR_MEMORY_BLOCK_ADDED = 20
    DOCR_MEMORY_BLOCK_REMOVED = 21
    # ... (all other constants)

    def __init__(self):
        pass

    def set_changed(self, type: int, old_value=None, new_value=None):
        pass

    def set_register_values_changed(self, register: 'Register', start: 'Address', end: 'Address'):
        pass

    def set_changed(self, type: int, start: 'Address', end: 'Address', old_value=None, new_value=None):
        pass

    def set_obj_changed(self, type: int, sub_type: int = None, obj: object = None, old_value=None, new_value=None):
        pass

    def set_obj_changed(self, type: int, addr: 'Address', obj: object = None, old_value=None, new_value=None):
        pass

    def set_obj_changed(self, type: int, sub_type: int = None, addr_set_view: 'AddressSetView' = None,
                        obj: object = None, old_value=None, new_value=None):
        pass

    def set_property_changed(self, property_name: str, code_unit_addr: 'Address', old_value=None, new_value=None):
        pass

    def set_property_range_removed(self, property_name: str, start: 'Address', end: 'Address'):
        pass
