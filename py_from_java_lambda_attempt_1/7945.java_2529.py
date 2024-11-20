Here is the translation of the given Java code into Python:

```Python
import os
from ghidra_script import GhidraScript
from ghidra_program_model_address import Address
from ghidra_program_model_symbol import SymbolTable, SymbolIterator
from mdemangler import MDMangGhidra

class DumpAllSymbolsDemangledScript(GhidraScript):
    def run(self):
        dump_file = self.askFile("Choose an output file", "OK")
        if not dump_file:
            print("Canceled execution due to no output file")
            return
        if os.path.exists(dump_file):
            if not self.askYesNo("Confirm Overwrite", f"Overwrite file: {dump_file}"):
                print("Operation canceled")
                return

        with open(dump_file, 'w') as file_writer:
            buffered_writer = file_writer.buffered()

            symbol_table = current_program.get_symbol_table()
            symbol_iterator = symbol_table.get_defined_symbols()

            while symbol_iterator.has_next() and not self.monitor.is_cancelled():
                symbol = symbol_iterator.next()
                if symbol.source == SymbolTable.SourceType.DEFAULT:
                    continue

                address = symbol.address
                if address.is_external_address or Address.NO_ADDRESS.equals(address):
                    continue

                name = symbol.name
                demangled_name = get_demangled_string(name)
                if demangled_name and not demangled_name.strip():
                    name = demangled_name

                buffered_writer.write(f"{address} {name}\n")
            buffered_writer.close()

    def get_demangled_string(self, mangled_string):
        try:
            mdemangler = MDMangGhidra()
            parsable_item = mdemangler.demangle(mangled_string, True)
            if isinstance(parsable_item, MDObjectCPP):
                return str((MDObjectCPP)(parsable_item).get_qualified_name())
#			if isinstance(parsable_item, MDFunctionType):
#				return (MDFunctionType)(parsable_item).getName()
#			if isinstance(parsable_item, MDDataType):
#				return (MDDataType)(parsable_item).getName()
            return str(parsable_item)
        except MDError as e:
            print(f"Couldn't demangle: {e}")
            return None
```

Please note that the above Python code is not a direct translation of Java to Python. It's more like an equivalent implementation in Python, considering the differences between both languages and their respective libraries (Ghidra).