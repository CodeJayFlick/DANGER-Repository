class Equate:
    def __init__(self):
        pass

    def get_name(self):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_display_name(self):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_value(self):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_display_value(self):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_reference_count(self):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def add_reference(self, ref_addr, opnd_position):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def rename_equate(self, new_name):
        if len(new_name) == 0:
            raise ValueError("Name cannot be empty")
        self._name = new_name

    @property
    def name(self):
        return self._name

    def get_references(self):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def get_references_at_address(self, ref_addr):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def remove_reference(self, ref_addr, opnd_position):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    def is_valid_uuid(self):
        return self._is_enum_based

    def is_enum_based(self):
        return self._is_enum_based

    @property
    def enum_uuid(self):
        if not self.is_enum_based:
            raise ValueError("Equate is not based on an enum")
        return self._enum_uuid

    def __str__(self):
        # TO DO: implement this method
        raise NotImplementedError("Method not implemented")

    _name = None
    _is_enum_based = False
    _enum_uuid = None
