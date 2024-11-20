class ReferenceDB:
    def __init__(self, from_addr, to_addr, ref_type, op_index, source_type, is_primary, symbol_id):
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.ref_type = ref_type
        self.op_index = op_index
        self.source_type = source_type
        self.is_primary = is_primary
        self.symbol_id = symbol_id

    def __eq__(self, other):
        return (isinstance(other, ReferenceDB) and 
                self.from_addr == other.from_addr and 
                self.to_addr == other.to_addr and 
                self.ref_type == other.ref_type and 
                self.op_index == other.op_index and 
                self.source_type == other.source_type)

    def get_from_address(self):
        return self.from_addr

    def get_reference_type(self):
        return self.ref_type

    def get_operand_index(self):
        return self.op_index

    def is_mnemonic_reference(self):
        return not self.is_operand_reference()

    def is_operand_reference(self):
        return self.op_index >= 0

    def __hash__(self):
        return hash(self.from_addr)

    def __str__(self):
        return f"From: {self.from_addr}, To: {self.to_addr}, Type: {self.ref_type}, Op: {self.op_index}, Source: {self.source_type}"

    def compare_to(self, other):
        if self.from_addr < other.get_from_address():
            return -1
        elif self.from_addr > other.get_from_address():
            return 1
        else:
            if self.op_index < other.get_operand_index():
                return -1
            elif self.op_index > other.get_operand_index():
                return 1
            else:
                if self.to_addr < other.get_to_address():
                    return -1
                elif self.to_addr > other.get_to_address():
                    return 1
                else:
                    return 0

    def get_symbol_id(self):
        return self.symbol_id

    def get_to_address(self):
        return self.to_addr

    def is_primary_reference(self):
        return self.is_primary

    # Note: The following methods are not implemented in the original Java code.
    #       You may need to add your own implementation based on your requirements.

    def is_external_reference(self):
        return False

    def is_memory_reference(self):
        return isinstance(self.to_addr, int)

    def is_register_reference(self):
        return isinstance(self.to_addr, str) and self.to_addr.startswith("R")

    def is_offset_reference(self):
        return False

    def is_shifted_reference(self):
        return False

    def is_entry_point_reference(self):
        return False

    def is_stack_reference(self):
        return False
