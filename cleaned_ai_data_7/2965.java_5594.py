import ghidra


class AddSingleReferenceInSwitchTable:
    def run(self):
        program = current_program()
        listing = program.get_listing()

        # Ask for base address 
        pc = ask_address("Enter switch base address (hex, don't use 0x):")

        # Get current data value
        data = listing.get_defined_data_at(current_address())
        curr_val = int(data.value().substring(2), 16)

        # Calculate referenced addr
        ref_addr = pc.add(curr_val * 2)

        print(f"Adding ref {ref_addr} to address {data.address_string(False, True)}")
        data.add_value_reference(ref_addr, ghidra.ghidra_data_ref_type.DATA)


if __name__ == "__main__":
    AddSingleReferenceInSwitchTable().run()
