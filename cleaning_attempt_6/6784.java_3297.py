import ghidra_app_scripting as GHS

class FindPotentialDecompilerProblems(GHS.GhidraScript):
    def run(self):
        if self.is_running_headless():
            print("This script cannot be run in headless mode.")
            return
        
        table_dialog = self.create_table_chooser_dialog(
            "Possible Decompiler Problems: " + str(current_program.name), None)
        
        self.configure_table_columns(table_dialog)

        entry_list = TableEntryList(table_dialog)

        callback = DecompilerCallback(self.current_program, BasicConfigurer(self.current_program))

        funcs_to_decompile = set()
        for func in current_program.get_function_manager().get_functions_no_stubs(True):
            funcs_to_decompile.add(func)
        
        if not funcs_to_decompile:
            self.popup("No functions to decompile!")
            return
        
        ParallelDecompiler.decompile_functions(callback, funcs_to_decompile, monitor)

    def process_func(self, decompile_results):
        problems = []
        func = decompile_results.get_function()
        high_func = decompile_results.get_high_function()

        if not high_func:
            problems.append(ProblemLocation(current_program, func.entry_point(), 
                func.entry_point(), "", "Decompilation Error"))
            return problems

        for sym in high_func.local_symbol_map().get_symbols():
            high_var = sym.high_variable()
            
            if isinstance(high_var, GHS.HighLocal):
                if sym.name.startswith("in_") and not sym.name == "in_FS_OFFSET":
                    possible = ("Function signature missing register param, called function passed too many register params, or only a subpiece of a register actually used.")
                    
                    if not high_func.function().symbol().is_global() and \
                        not high_func.function().calling_convention_name().contains("thiscall"):
                        possible += " Function might need calling convention changed to thiscall"
                    
                    if sym.name.startswith("in_stack_ff"):
                        possible = ("Too many stack parameters passed to a called function.  May need to redefine in the called function (could be varargs).")
                    elif sym.name.startswith("in_stack_00"):
                        possible = ("Too few stack parameters defined for this function.  May need to redefine parameters.")
                    
                    func_addr = self.get_first_func_with_var(func, high_var.representative())
                    
                    if not func_addr or func_addr == GHS.Address.NO_ADDRESS:
                        func_addr = func.entry_point()
                    
                    problems.append(ProblemLocation(current_program, func.entry_point(), 
                        func_addr, sym.name, possible))
                elif sym.name.startswith("unaff_"):
                    first_addr = self.get_first_called_function(func)
                    
                    if not first_addr or first_addr == GHS.Address.NO_ADDRESS:
                        problems.append(ProblemLocation(current_program, current_program.function_manager().get_function_at(first_addr).entry_point(), 
                            func.entry_point(), sym.name, "Suspect function is EH_PROLOG/EH_EPILOG"))
                elif sym.name.startswith("extraout"):
                    first_addr = self.get_first_func_with_var(func, high_var.representative())
                    
                    if not first_addr or first_addr == GHS.Address.NO_ADDRESS:
                        func_addr = func.entry_point()
                    
                    possible = ("Bad parameter in called function or extra return value/global register/function register side effect")
                    
                    if sym.name.startswith("extraout_var"):
                        possible = "Function containing problem may need return type adjusted."
                    
                    problems.append(ProblemLocation(current_program, current_program.function_manager().get_function_at(first_addr).entry_point(), 
                        func_addr, sym.name, possible))
                else:
                    continue
            else:
                continue
        
        return problems

    def get_first_func_with_var(self, func, var):
        variable_addr = var.address()
        
        if not variable_addr:
            return GHS.Address.NO_ADDRESS
        
        ref_iter = func.program().reference_manager().get_reference_iterator(func.entry_point())
        
        max_addr = func.body().max_address()

        for ref in CollectionUtils.as_itterable(ref_iter):
            if not func.body().contains(ref.from_address()):
                continue
            
            if self.is_valid_call_reference(ref):
                return ref.to_address()
            
            if ref.from_address().compareTo(max_addr) > 0:
                return GHS.Address.NO_ADDRESS
        
        return GHS.Address.NO_ADDRESS

    def get_first_called_function(self, func):
        ref_iter = func.program().reference_manager().get_reference_iterator(func.entry_point())
        
        max_addr = func.body().max_address()

        for ref in CollectionUtils.as_itterable(ref_iter):
            if not func.body().contains(ref.from_address()):
                continue
            
            if self.is_valid_call_reference(ref):
                return ref.to_address()
            
            if ref.from_address().compareTo(max_addr) > 0:
                return GHS.Address.NO_ADDRESS
        
        return GHS.Address.NO_ADDRESS

    def is_valid_call_reference(self, ref):
        if not ref.reference_type().is_call():
            return False
        
        if not ref.to_address():
            return False
        
        if current_program.function_manager().get_function_at(ref.to_address()):
            return True
        
        return False

class BasicConfigurer(GHS.DecompileConfigurer):
    def __init__(self, prog):
        self.p = prog
    
    def configure(self, decompiler):
        decompiler.toggle_c_code(True)
        decompiler.toggle_syntax_tree(True)
        decompiler.set_simplification_style("decompile")
        
        opts = GHS.DecompileOptions()
        opts.grab_from_program(self.p)
        decompiler.set_options(opts)

class TableEntryList:
    def __init__(self, table_dialog):
        self.table_dialog = table_dialog
    
    def add(self, location):
        self.table_dialog.add(location)
    
    def set_message(self, string):
        self.table_dialog.set_message(string)
    
    def get_num_entries(self):
        return self.table_dialog.get_row_count()

class ProblemLocation:
    def __init__(self, program, problem_address, cause_address, var_name, explanation):
        self.program = program
        self.problem_address = problem_address
        self.cause_address = cause_address
        self.var_name = var_name
        self.explanation = explanation
    
    def get_program(self):
        return self.program
    
    def get_address(self):
        if not self.problem_address:
            return GHS.Address.NO_ADDRESS
        
        return self.problem_address

    def get_func_addr(self):
        if not self.problem_address:
            return GHS.Address.NO_ADDRESS
        
        return self.problem_address

    def get_why_addr(self):
        if not self.cause_address:
            return GHS.Address.NO_ADDRESS
        
        return self.cause_address
    
    def get_var_name(self):
        return self.var_name
    
    def get_explanation(self):
        return self.explanation
    
    def __str__(self):
        return "Issue at: {} found: {} {}".format(self.get_func_addr(), 
            self.var_name, self.explanation)
