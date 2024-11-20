class FunctionLocation:
    def __init__(self, program, location_addr, function_addr):
        self.program = program
        self.location_addr = location_addr
        self.function_addr = function_addr

    @staticmethod
    def from_xml():
        pass  # Default constructor needed for restoring a program function location from XML

    def equals(self, obj):
        if super().equals(obj):  # Check the parent class's equality method
            return self.compare_addresses(self.function_addr, (obj).function_addr) == 0
        return False

    @staticmethod
    def compare_addresses(addr1, addr2):
        pass  # Compare two addresses for equality

    def get_function_address(self):
        return self.function_addr

    def save_state(self, obj):
        super().save_state(obj)
        if self.function_addr is not None:
            obj['_FUNC_ADDRESS'] = str(self.function_addr)

    @classmethod
    def restore_state(cls, program1, obj):
        cls.save_state(program1, obj)  # Save the state of this function location

    @staticmethod
    def get_address(program1, address_string):
        if address_string is None:
            return None  # Default to None in case no valid address string provided
        new_addr = ProgramUtilities.parse_address(program1, address_string)
        return new_addr if new_addr else None  # Return the parsed address or default

    def is_valid(self, program):
        if not super().is_valid(program):  # Check parent class's validity method
            return False
        listing = program.get_listing()
        if self.location_addr != self.function_addr:
            inferred_function_ref = listing.get_function_at(self.location_addr)
            if inferred_function_ref is None:  # Ensure the function reference exists and points to this address
                return False
        code_unit = listing.get_code_unit_at(self.location_addr)
        if not isinstance(code_unit, Data):  # Check that it's a data type (e.g., pointer or integer)
            return False
        ref = code_unit.get_primary_reference(0)  # Get the primary reference for this address
        if ref is None or ref.get_to_address() != self.function_addr:  # Ensure the function reference points to this address
            return False
        return True

    def __str__(self):
        if self.location_addr == self.function_addr:
            return super().__str__()
        return f"{super().__str__()} function_addr={self.function_addr}"
