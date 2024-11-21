import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import *
from ghidra.program.model.symbol.EquateTable import EquateTable
from ghidra.util.collection import CollectionUtils

class ShowEquatesInSelectionScript(GhidraScript):
    def run(self):
        scope = self.current_selection
        if scope is None:
            function = self.get_function_containing(self.current_address)
            if function is None:
                print("Please make a selection or place the cursor in a function")
                return

            scope = function.getBody()

        equate_table = self.current_program.getEquateTable()
        it = equate_table.getEquateAddresses(scope)
        addresses = list(it)
        show(addresses)

if __name__ == "__main__":
    script = ShowEquatesInSelectionScript()
    script.run()
