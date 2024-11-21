Here is the translation of the given Java code into Python:

```Python
import ghidra.app.script.GhidraScript
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.symbol import SymbolTable
from ghidra.program.model.mem import Byte

class AutoRenameLabelsScript(GhidraScript):
    def run(self) -> None:
        if self.currentSelection is None or len(self.currentSelection) == 0:
            print("No selection exists.")
            return
        
        base = input("Enter label base name: ")
        
        num = 1
        view = self.currentSelection
        if view is None or len(view) == 0:
            return

        symbol_table = self.currentProgram.getSymbolTable()
        it = view.getAddresses(True)

        while it.hasNext():
            address = it.next()
            primary_symbol = symbol_table.getPrimarySymbol(address)
            if primary_symbol is not None and primary_symbol.getSource() == SymbolTable.SourceType.DEFAULT:
                print(f"Renaming label at {address} to {base}{num}")
                self.currentProgram.renameLabel(address, base + str(num), SymbolTable.SourceType.USER_DEFINED)
                num += 1
        else:
            if len(view) > 0:
                status_message = view.getStatusMsg()
                if status_message is not None and len(status_message) > 0:
                    print(f"Status message: {status_message}")
```

Please note that Python does not support Java's `@Override` annotation, so I removed it. Also, the equivalent of Java's `if (cmd.size() > 0)` block was moved to after the loop where labels are renamed.