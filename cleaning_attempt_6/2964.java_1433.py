import ghidra


class AddReferencesInSwitchTable:
    def run(self):
        print("This script attempts to add references to a switch table to corresponding code.\n"
              "BEFORE running this script,\n"
              "     1. Your switch table should already be defined data.\n"
              "     2. Make sure your cursor is on the \"add pc, ..\" command.\n"
              "Note: Adding the same reference twice does not have any impact.")
        
        program = ghidra.currentProgram
        listing = program.getListing()
        
        start_addr = ghidra.currentAddress
        pc = start_addr.add(4)
        
        prev_addr = None
        diff = 0
        
        # Get data iterator
        data_iter = listing.getDefinedData(start_addr, True)
        
        # Find and add reference to first table entry
        data = next(data_iter)
        self.CalcAndAddReference(data, pc)
        prev_addr = data.getMinAddress()
        
        # Determine address difference between each switch table entry
        type = data.getDataType()
        if str(type.getName()).lower() == "byte":
            diff = 1
        elif str(type.getName()).lower() == "word":
            diff = 2
        elif str(type.getName()).lower() == "dword":
            diff = 4
        else:
            print("Sorry, type {} is not supported yet. (Try adding it yourself.)")
            return
        
        # Iterate through rest of table
        while data_iter.hasNext():
            if ghidra.util.taskmonitor.isCancelled():
                break
            
            data = next(data_iter)
            curr_addr = data.getMinAddress()
            
            # Check if consecutive next entry in switch table
            if curr_addr.subtract(prev_addr) == diff:
                prev_addr = curr_addr
                
                # Add reference
                self.CalcAndAddReference(data, pc)
            else:
                break
        
    def CalcAndAddReference(self, data, pc):
        # Get current data value in switch table
        curr_val = int(data.getValue().toString()[2:], 16)
        
        # Calculate referenced addr
        ref_addr = pc.addWrap(curr_val * 2)
        
        # Add reference
        print("Adding ref {} to address {}".format(ref_addr.toString(), data.getAddressString(False, True)))
        data.addValueReference(ref_addr, ghidra.program.model.symbol.RefType.COMPUTED_JUMP)


if __name__ == "__main__":
    script = AddReferencesInSwitchTable()
    try:
        script.run()
    except Exception as e:
        print("An error occurred: {}".format(e))
