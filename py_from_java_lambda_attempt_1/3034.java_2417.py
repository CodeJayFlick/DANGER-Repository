Here is the translation of the given Java code into Python:

```Python
import ghidra.app.script.GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Listing, InstructionIterator, DataIterator

class FindOverlappingCodeUnitsScript(GhidraScript):
    def run(self):
        set = AddressSet()
        listing = self.currentProgram.getListing()
        instr_iter = listing.getInstructions(True)
        
        while instr_iter.hasNext() and not self.monitor.isCancelled():
            instruction = instr_iter.next()
            self.monitor.setMessage(str(instruction.getMinAddress()))
            length = instruction.getLength()
            
            for i in range(1, length):
                addr = instruction.getMinAddress().add(i)
                
                if listing.getInstructionAt(addr) is not None or listing.getDefinedDataAt(addr) is not None:
                    set.addRange(addr, addr)

        data_iter = listing.getDefinedData(True)
        
        while data_iter.hasNext() and not self.monitor.isCancelled():
            data = data_iter.next()
            self.monitor.setMessage(str(data.getMinAddress()))
            length = data.getLength()
            
            for i in range(1, length):
                addr = data.getMinAddress().add(i)
                
                if listing.getInstructionAt(addr) is not None or listing.getDefinedDataAt(addr) is not None:
                    set.add(addr)

        if set.getNumAddresses() == 0:
            print("No overlapping codeunits found!")
            return

        self.show("Overlapping Code Units", set)
```

Please note that this Python script assumes you have the `ghidra` library installed and imported.