Here is the translation of the given Java code into Python:

```Python
import ghidra.app.decompiler.DecompInterface as DecompInterface
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Listing
from ghidra.program.model.symbol import Reference, Symbol
from ghidra.framework.options import ToolOptions

class ShowCCallsScript:
    def __init__(self):
        self.last_addr = None

    def run(self):
        if current_location is None:
            print("No Location.")
            return

        listing = current_program.get_listing()
        func = listing.get_function_containing(current_address)

        if func is None:
            print(f"No Function at address {current_address}")
            return

        decomp_interface = setUpDecompiler(current_program)
        
        try:
            if not decomp_interface.open_program(current_program):
                print(f"Decompile Error: {decomp_interface.get_last_message()}")
                return
            
            # call decompiler for all refs to current function
            sym = self.get_symbol_at(func.get_entry_point())
    
            refs = sym.get_references(None)
            
            for i in range(len(refs)):
                if monitor.is_cancelled():
                    break
                
                ref_addr = refs[i].get_from_address()
                ref_func = current_program.get_function_manager().get_function_containing(ref_addr)

                if ref_func is None:
                    continue

                # decompile function
                # look for call to this function
                # display call
                self.analyze_function(decomp_interface, current_program, ref_func, ref_addr)
        finally:
            decomp_interface.dispose()
        
        self.last_addr = None
    
    def setUpDecompiler(self, program):
        decomp_interface = DecompInterface()

        options = DecompileOptions() 
        service = state.get_tool().get_service(OptionsService)
        if service is not None:
            tool_options = service.get_options("Decompiler")
            options.grab_from_tool_and_program(None,tool_options,program)    
        
        decomp_interface.set_options(options)

        decomp_interface.toggle_c_code(True)
        decomp_interface.toggle_syntax_tree(True)
        decomp_interface.set_simplification_style("decompile")

        return decomp_interface

    def analyze_function(self, decomp_interface, program, f, ref_addr):
        if f is None:
            return
        
        # don't decompile the function again if it was the same as the last one
        #
        if not f.get_entry_point().equals(self.last_addr):
            self.decompile_function(f, decomp_interface)
        
        self.last_addr = f.get_entry_point()

        instr = program.get_listing().get_instruction_at(ref_addr)

        if instr is None:
            return
        
        print(self.print_call(f, ref_addr))
    
    def decompile_function(self, f, decomp_interface):
        # decomplib.setSimplificationStyle("normalize", null);
        high_function = decomp_interface.decompile_function(f)
        
        decomp_results = decomp_interface.decompile_function(f, decomp_interface.get_options().get_default_timeout(), monitor)

        self.high_function = decomp_results.get_high_function()
        docroot = decomp_results.get_c_code_markup()

        if self.high_function is None:
            return False
        
        return True
    
    def print_call(self, f, ref_addr):
        buff = StringBuffer()

        self.print_call(ref_addr, docroot, buff, False, False)

        return buff.toString()
    
    def print_call(self, ref_addr, node, buff, did_start, is_call):
    	if node is None:
    		return False

    	min_addr = node.get_min_address()
        max_addr = node.get_max_address()

        if min_addr is None:
            return False
        
        if ref_addr.get_physical_address().equals(max_addr) and isinstance(node, ClangStatement): 
        	clang_statement = (ClangStatement)node
        		if not did_start: 
        			buff.append(f" {ref_addr.get_physical_address()} : ")
        		buff.append("    " + self.toString(clang_statement))
        	return True
        
        for j in range(len(node.children)):
            is_call |= isinstance(node.child(j), ClangStatement)
            did_start |= self.print_call(ref_addr, node.child(j), buff, did_start, is_call)

        return did_start
    
    def toString(self, node):
    	buffer = StringBuffer()
    	open=-1
    	for j in range(len(node.children)):
        	clang_node = node.child(j)
        	if isinstance(clang_node, ClangSyntaxToken): 
        		clang_syntax_token = (ClangSyntaxToken) clang_node
        		if clang_syntax_token.get_open() != -1: 
        			continue
        
        	if open != -1:
            	break

        return buffer.toString()
```

Note that the above Python code is not a direct translation of the given Java code. It's more like an interpretation of how you could translate it into Python, as there are some differences between the two languages and their respective libraries.