import os
from ghidra_scripts import GhidraScript, SymbolTable, Memory, Address, SymbolIterator

class VxWorksSymTab_6_1(GhidraScript):
    def run(self):
        # Get memory and symbol table objects (used later)
        mem = self.currentProgram.getMemory()
        sym_tbl = self.currentProgram.getSymbolTable()

        try:
            output_file_name = askFile("vxWorks Symbol Table Parser", "Output file name?")
            with open(output_file_name, 'w') as f:
                # Get address of "total number of symbol table entries" value
                vx_num_sym_entries_addr = askAddress("vxWorks Symbol Table Parser",
                                                       "Address of \"total number of symbol table entries\" value?")
                vx_num_sym_entries = mem.getInt(vx_num_sym_entries_addr)
                print(f"VxWorks symbol table has {vx_num_sym_entries} entries")

                # Create a GNU demangler instance
                try:
                    demangler = GnuDemangler()
                    if not demangler.can_demangle(self.currentProgram):
                        print("Unable to create demangler.")
                        return

                    # Process entries in VxWorks symbol table
                    vx_sym_tbl_addr = vx_num_sym_entries_addr.subtract(vx_num_sym_entries * 24)
                    for i in range(vx_num_sym_entries):
                        if self.monitor.isCancelled():
                            return

                        print(f"i={i}")  # visual counter

                        # Extract symbol table entry values
                        sym_entry_addr = vx_sym_tbl_addr.add(i * 24)
                        sym_name_addr = Address(mem.getInt(sym_entry_addr + 4))
                        sym_loc_addr = Address(mem.getInt(sym_entry_addr + 8))
                        sym_type = mem.getByte(sym_entry_addr + 0x14)

                        print(f"symNameAddr: {hex(sym_name_addr)}, symLocAddr: {hex(sym_loc_addr)}, symType: {sym_type}")

                        # Remove any data or instructions that overlap this symName
                        a = sym_name_addr
                        while mem.getByte(a) != 0:
                            if getDataAt(a):
                                removeDataAt(a)
                            elif getInstructionAt(a):
                                removeInstructionAt(a)

                    for a in range(sym_name_addr, sym_name_addr + 1):
                        if getDataAt(a):
                            removeDataAt(a)
                        elif getInstructionAt(a):
                            removeInstructionAt(a)

                except Exception as e:
                    print(f"createAsciiString: caught exception... {e}")
                    return

        finally:
            pass
