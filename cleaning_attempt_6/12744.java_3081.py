class ChangeManagerAdapter:
    def set_changed(self, type: int, start_address=None, end_address=None, old_value=None, new_value=None):
        # Default implementation does nothing.
        pass

    def set_changed(self, type: int, old_value=None, new_value=None):
        # Default implementation does nothing.
        pass

    def set_obj_changed(self, type: int, sub_type=None, address=None, affected_object=None, old_value=None, new_value=None):
        # Default implementation does nothing.
        pass

    def set_obj_changed(self, type: int, addr_set_view=None, affected_object=None, old_value=None, new_value=None):
        # Default implementation does nothing.
        pass

    def set_obj_changed(self, type: int, affected_object=None, old_value=None, new_value=None):
        # Default implementation does nothing.
        pass

    def set_obj_changed(self, type: int, sub_type=None, affected_object=None, old_value=None, new_value=None):
        # Default implementation does nothing.
        pass

    def set_property_changed(self, property_name: str, code_unit_address=None, old_value=None, new_value=None):
        # Default implementation does nothing.
        pass

    def set_property_range_removed(self, property_name: str, start_address=None, end_address=None):
        # Default implementation does nothing.
        pass

    def set_register_values_changed(self, register: object, start_address=None, end_address=None):
        # Default implementation does nothing.
        pass
