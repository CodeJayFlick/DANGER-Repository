import ghidra.app.script.GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import AlignmentDataType
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import MemoryBlock

class CondenseAllRepeatingBytes(GhidraScript):
    def run(self) -> None:
        if self.currentAddress is None:
            print("No Location.")
            return
        
        listing = self.currentProgram.getListing()
        
        current_addr = self.currentAddress
        memory_block = self.currentProgram.getMemory().getBlock(current_addr)
        symbol_table = self.currentProgram.getSymbolTable()

        if memory_block.isInitialized():
            repeating_byte = self.currentProgram.getMemory().getByte(current_addr)            
            rep_string_no0x = hex(repeating_byte & 0xff)

            print(f"Condensing all runs of {minRepeatLen} or more '{rep_string_no0x}'s in the '{memory_block.getName()}' memory block.")

            min_repeat_len = 5
            repeating_bytes = [repeating_byte] * min_repeat_len
            repeat_len = min_repeat_len

            start_addr = current_addr
            same_memory_block = True
            
            while ((current_addr := self.find(start_addr, bytes(repeating_bytes))) is not None) and (same_memory_block):
                if listing.isUndefined(current_addr, current_addr.add(minRepeatLen - 1)):
                    i = 0                    
                    while (i < min_repeat_len) and (same_memory_block):
                        if memory_block.equals(self.currentProgram.getMemory().getBlock(current_addr.add(i))):
                            same_memory_block = True
                            i += 1
                        else:
                            same_memory_block = False

                is_undef = True
            else:
                is_undef = False
                current_addr = current_addr.add(1)

            if (is_undef) and (same_memory_block):
                start_addr = current_addr
                current_addr = current_addr.add(minRepeatLen)
                no_data_collisions = listing.isUndefined(current_addr, current_addr)
                no_label_collisions = symbol_table.hasSymbol(current_addr)
                
                while ((current_addr := self.find(start_addr, bytes(repeating_bytes))) is not None) and (same_memory_block) and (self.currentProgram.getMemory().getByte(current_addr) == repeating_byte) and (no_data_collisions) and (not no_label_collisions):
                    repeat_len += 1
                    current_addr = current_addr.add(1)
                    
                listing.createData(start_addr, AlignmentDataType(), repeat_len)

                print(f"Applied Alignment datatype at {start_addr.toString()}")

        else:
            print("Script does not work in uninitialized memory.")
