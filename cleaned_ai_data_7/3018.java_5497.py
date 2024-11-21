import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import DataType
from ghidra.program.model.listing import CodeUnitIterator, Instruction

class EditBytesScript(GhidraScript):
    def run(self):

        new_bytes = None
        end_addr = None
        active_addr = None
        code_end = None
        contained_in_block = False

        while not contained_in_block:
            self.monitor.checkCanceled()
            new_bytes = input("Replace Bytes: ")
            end_addr = self.current_location.get_byte_address().add(len(new_bytes) - 1)
            active_addr = self.current_location.get_byte_address()

            contained_in_block = self.current_program.get_memory().get_block(active_addr).contains(end_addr)

            if contained_in_block:
                break

        start_addr = self.current_location.get_byte_address()
        active_addr = self.current_program.get_listing().get_code_unit_containing(active_addr).get_address()
        addr_set = AddressSet(active_addr, end_addr)
        code_units_iter = self.current_program.get_listing().get_code_units(addr_set, True)

        code_addr_set = None

        addr_to_data_type_map = {}
        addr_to_code_map = {}

        while code_units_iter.hasNext():
            active_addr = code_units_iter.next().get_address()

            data = self.get_data_at(active_addr)
            if data is not None:
                data_type = data.get_data_type()
                addr_to_data_type_map[active_addr] = data_type
                continue

            instruction = self.get_instruction_containing(active_addr)
            if instruction is not None:
                code_end = active_addr.add(instruction.get_length() - 1)
                code_addr_set = AddressSet(active_addr, code_end)
                addr_to_code_map[active_addr] = code_addr_set
                continue

        self.clear_listing(start_addr, end_addr)

        try:
            self.set_bytes(start_addr, new_bytes.encode())
        except Exception as e:
            print("Bytes cannot be set on uninitialized memory")
            return

        for entry in addr_to_data_type_map.items():
            try:
                self.create_data(entry[0], entry[1])
            except Exception as e:
                # leaves bytes undefined if there is no 00 byte at the end to
                # make a null terminated string 
                return

        for entry in addr_to_code_map.items():
            cmd = DisassembleCommand(entry[0], entry[1], True)
            cmd.apply_to(self.current_program, self.monitor)

