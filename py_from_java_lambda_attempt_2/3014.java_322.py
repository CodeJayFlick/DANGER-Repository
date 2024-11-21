Here is the translation of the given Java code into Python:

```Python
import ghidra.app.cmd.label.DemanglerCmd
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import Symbol
from ghidra.program.util import *
from docking import *

class DemangleSymbolScript:
    def run(self):
        window_manager = DockingWindowManager.getActiveInstance()
        provider = window_manager.getActiveComponentProvider()
        action_context = provider.getActionContext(None)
        
        if isinstance(action_context, ProgramSymbolActionContext):
            for s in action_context.getSymbols():
                self.demangle(s.getAddress(), s.getName())
                
        elif isinstance(current_location, FunctionSignatureFieldLocation):
            function = get_function_at(current_address)
            if function is not None:
                self.demangle(current_address, function.getName())

        elif isinstance(current_location, LabelFieldLocation):
            lfl = current_location
            self.demangle(current_address, lfl.getName())
            
        elif isinstance(current_location, OperandFieldLocation):
            data = get_data_at(current_address)
            if data is None:
                return

            value = data.getValue()
            if not isinstance(value, Address):
                return
            
            symbol_addr = value
            sym = get_symbol_at(symbol_addr)
            if sym is None:
                popup("Symbol not found at the address " + str(symbol_addr) +
                      " referenced by the selected pointer")
                return
                
            self.demangle(symbol_addr, sym.getName())
            
        else:
            sym = get_symbol_at(current_address)
            if sym is not None:
                self.demangle(current_address, sym.getName())
            else:
                print("Nothing to demangle at " + str(current_address))
                
    def demangle(self, address, name):
        if name.startswith('s_') or name.startswith('u_') or name.startswith('AddrTable'):
            print("Not a mangled name: " + name)
            return
            
        if '::case_0x' in name:
            pos = name.index('::case_0x')
            name = name[:pos]
            
        elif '::switchTable' in name:
            pos = name.index('::switchTable')
            name = name[:pos]

        cmd = DemanglerCmd(address, name)
        success = cmd.apply_to(current_program, monitor)
        
        if success:
            print("Successfully demangled!\n" + name + '\n' + str(cmd.getResult()))
            
        else:
            print(str(cmd.getStatusMsg()))

# This is the main function
if __name__ == "__main__":
    script = DemangleSymbolScript()
    try:
        script.run()
    except Exception as e:
        print("An error occurred: " + str(e))
```

Please note that this code assumes you have a Python version of Ghidra's API, which is not publicly available.