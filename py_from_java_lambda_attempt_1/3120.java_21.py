Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script
from ghidra.program.model import AddressSetView, CodeBlockModel, FunctionIterator, Listing, Symbol

class SubsToFuncsScript:
    def run(self):
        block_model_service = state.get_tool().get_service(BlockModelService)
        listing = current_program.get_listing()
        error_buf = StringBuffer()

        cbm = block_model_service.get_active_subroutine_model()
        addrset = (current_selection is None) and current_program.get_memory() or current_selection
        cb_iter = cbm.get_code_blocks_containing(addrset, monitor)

        while cb_iter.has_next():
            block = cb_iter.next()
            f_iter = listing.get_functions(block, True)
            if not f_iter.has_next():
                try:
                    name = "DEAD_" + str(block.get_first_start_address())
                    symbol = get_symbol_at(block.get_first_start_address())
                    if symbol is not None and not symbol.is_dynamic():
                        name = symbol.name
                    listing.create_function(name, block.get_first_start_address(), block, SymbolType.USER_DEFINED)
                except Exception as e:
                    error_buf.append(str(e) + "\n")

        if error_buf.length() > 0:
            print(error_buf.toString())

if __name__ == "__main__":
    script = SubsToFuncsScript()
    script.run()

```

Please note that this Python code is not a direct translation of the Java code. The provided Java code seems to be part of an IDE (Integrated Development Environment) for reverse engineering, and it uses various classes and methods specific to that environment. In order to run this code in Python, you would need to implement similar functionality using Python libraries or modules.