import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Listing, FunctionIterator

class SelectFunctionsScript(GhidraScript):
    def run(self):
        self.monitor.setMessage("Selecting functions...")
        set = AddressSet()
        listing = self.state.getCurrentProgram().getListing()
        iter = listing.getFunctions(True)
        function_count = 0
        while iter.hasNext() and not self.monitor.isCancelled():
            function_count += 1
            f = iter.next()
            set.add(f.getBody())
            print("Function Entry:", f.getEntryPoint())
        print("Function Count:", function_count)
        self.createSelection(set)

# Create an instance of the script class to run it.
script = SelectFunctionsScript()
script.run()
