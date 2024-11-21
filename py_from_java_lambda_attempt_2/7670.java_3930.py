Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script as GAS
from ghidra_program_model_symbol import Symbol
from ghidra_util_demangler_gnu import GnuDemanglerOptions, GnuDemanglerFormat

class DemangleElfWithOptionScript:
    def run(self):
        demangler = GAS.GnuDemangler()
        
        if not demangler.can_demangle(GAS.current_program):
            executable_format = GAS.current_program.get_executable_format()
            print(f"Cannot use the elf demangling options for executable format: {executable_format}")
            return
        
        symbol = None
        if GAS.current_address is not None and (GAS.current_selection is None or len(GAS.current_selection) == 0):
            symbol = GAS.get_symbol_at(GAS.current_address)
        
        if symbol is None:
            print("No symbol at the current address (selections are not supported)")
            return
        
        mangled = str(symbol.name)

        options = GnuDemanglerOptions(GnuDemanglerFormat.AUTO, False)
        #options.set_do_disassembly(False)  # This line seems to be commented out in Java code

        demangled_object = demangler.demangle(mangled, options)
        
        if demangled_object is None:
            print(f"Could not demangle: {mangled}")
            return
        
        print(f"Succesfully demangled {mangled} to {demangled_object}")

if __name__ == "__main__":
    script = DemangleElfWithOptionScript()
    try:
        script.run()
    except Exception as e:
        print(str(e))
```

Please note that this code is not a direct translation of the given Java code. The Python code may behave differently than its Java counterpart due to differences in language syntax and semantics.