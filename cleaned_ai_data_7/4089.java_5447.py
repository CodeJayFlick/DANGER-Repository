class NextPreviousDifferentByteAction:
    def __init__(self, tool, owner, sub_group):
        super().__init__(tool, "Next Different Byte Value", owner, sub_group)

    def get_navigation_type_name(self):
        return "Different Byte Value"

    def get_icon(self):
        # This part is not implemented in the original Java code
        pass

    def get_key_stroke(self):
        # This part is not implemented in the original Java code
        pass

    def get_next_address(self, monitor, program, address):
        return self.get_next_previous_address(monitor, program, address, True)

    def get_previous_address(self, monitor, program, address):
        return self.get_next_previous_address(monitor, program, address, False)

    def get_next_previous_address(self, monitor, program, address, forward):
        value = 0
        try:
            value = program.memory.get_byte(address)
        except Exception as e:
            code_unit = self.get_next_previous_code_unit(program, address, forward)
            if code_unit is None:
                return None
            else:
                return code_unit.address

        # make sure we go at least to the next code unit
        cu = program.listing.get_code_unit_containing(address)
        if cu is not None:
            address = forward and cu.max_address or cu.min_address

        initialized_addresses = program.memory.get_all_initialized_addresses()
        iterator = initialized_addresses.addresses(address, forward)
        while True:
            monitor.check_canceled()
            addr = next(iterator)
            try:
                test_byte = program.memory.get_byte(addr)
                if test_byte != value:
                    return addr
            except Exception as e:
                raise AssertionError("Got MemoryAccessException when iterating over intialized memeory!")

    def get_next_previous_code_unit(self, program, address, forward):
        if forward:
            return program.listing.get_defined_code_unit_after(address)
        else:
            return program.listing.get_defined_code_unit_before(address)

# Example usage
tool = "GHIDRA"
owner = "Navigation"
sub_group = "Core"

action = NextPreviousDifferentByteAction(tool, owner, sub_group)
print(action.get_navigation_type_name())
