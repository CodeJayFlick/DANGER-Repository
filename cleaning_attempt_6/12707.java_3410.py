class ThunkReference:
    OPINDEX = 'OTHER'

    def __init__(self, from_addr, to_addr):
        self.from_addr = from_addr
        self.to_addr = to_addr

    @property
    def get_from_address(self):
        return self.from_addr

    @property
    def get_to_address(self):
        return self.to_addr

    def is_primary(self):
        return False

    def get_symbol_id(self):
        return -1

    def get_reference_type(self):
        return 'THUNK'

    def get_operand_index(self):
        return self.OPINDEX

    def is_mnemonic_reference(self):
        return True

    def is_operand_reference(self):
        return False

    def __eq__(self, other):
        if not isinstance(other, ThunkReference):
            return NotImplemented
        return (other.get_reference_type() == 'THUNK' and 
                self.from_addr == other.get_from_address() and 
                self.to_addr == other.get_to_address())

    @property
    def is_external_reference(self):
        return False

    @property
    def is_offset_reference(self):
        return False

    @property
    def is_shifted_reference(self):
        return False

    @property
    def is_entry_point_reference(self):
        return False

    @property
    def is_memory_reference(self):
        return False

    @property
    def is_register_reference(self):
        return False

    @property
    def is_stack_reference(self):
        return False

    @property
    def get_source(self):
        return 'DEFAULT'
