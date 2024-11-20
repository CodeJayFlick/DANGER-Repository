import os
from ghidra.program.model import Memory
from ghidra.program.model.address import AddressSet
from ghidra.program.model.reloc import RelocationTable
from ghidra.util.exception import CancelledException

class ExportProgramScript:
    def run(self):
        if current_program is None:
            print("Must have an open program")
            return
        
        out_binary_file = ask_file("Select Binary Output File", "Binary File")

        if os.path.exists(out_binary_file):
            if not ask_yes_no("Binary File Already Exists",
                              "The binary file already exists.\nDo you want to overwrite it?"):
                return

        relocation_addrs = AddressSet()

        reloc_table = current_program.get_relocation_table()
        for reloc in reloc_table:
            monitor.check_cancelled()
            start_addr = reloc.get_address()
            rloc_len = reloc.get_bytes().length
            relocation_addrs.add(start_addr, start_addr + rloc_len)

        out_file = open(out_binary_file, 'wb')

        memory = current_program.get_memory()
        all_file_bytes = list(memory.get_all_file_bytes())
        
        if not all_file_bytes:
            print("Cannot access original file bytes. Either the program was imported before Ghidra started saving original file bytes or the program was not imported directly from the original binary.")
            out_file.close()
            return

        #TODO: update to handle multiple case once FileBytes adds new method to support it
        if len(all_file_bytes) > 1:
            print("*** This program was created using multiple imported programs. This script will currently only work if the program was created with a single imported file.")
            out_file.close()
            return

        file_bytes = all_file_bytes[0]
        
        size = file_bytes.get_size()
        print(f"Exporting current program to a new binary file including any changes to the original except for relocation changes...")

        # compare each original imported byte with the current program byte at the equivalent location
        # if the current byte is different and is not a relocation, export that byte instead of 
        # the original
        for i in range(size):
            monitor.check_cancelled()
            
            original_byte = file_bytes.get_original_byte(i)
            current_byte = file_bytes.get_modified_byte(i)

            if original_byte != current_byte:
                addresses = memory.locate_addresses_for_file_offset(i)

                if not any(address in relocation_addrs for address in addresses):
                    print(f"{addresses}: Writing out changed byte since it is not a relocation. File offset = {i}, originalByte = {original:02x}, changed to = {current:02x}")
                    print("******")
                    out_file.write(current_byte)
                else:
                    # Not writing out change since it is a relocation
                    out_file.write(original_byte)

            else:
                out_file.write(original_byte)

        out_file.close()
        print("Done!")

    def ask_yes_no(self, prompt, message):
        while True:
            response = input(f"{prompt} ({message}) [y/n]: ")
            if response.lower() in ['yes', 'y']:
                return True
            elif response.lower() in ['no', 'n']:
                return False

    def ask_file(self, prompt, file_type):
        while True:
            filename = input(f"{prompt} {file_type}: ")
            if os.path.exists(filename):
                return filename
