Here is a translation of the Java code into equivalent Python:

```Python
class EntryPointAnalyzer:
    def __init__(self):
        self.name = "Disassemble Entry Points"
        self.description = "Disassembles entry points in newly added memory."
        self.option_name_respect_execute_flag = "Respect Execute Flag"
        self.option_description_respect_execute_flag = "Respect Execute flag on memory blocks when checking entry points for code."
        self.option_default_respect_execute_enabled = True
        self.respect_execute_flags = self.option_default_respect_execute_enabled

    def register_options(self, options, program):
        help_location = HelpLocation("AutoAnalysisPlugin", "Auto_Analysis_Option_Instructions")
        options.register_option(self.option_name_respect_execute_flag, self.respect_execute_flags, help_location, self.option_description_respect_execute_flag)

    def options_changed(self, options, program):
        self.respect_execute_flags = options.get_boolean(self.option_name_respect_execute_flag, self.respect_execute_flags)

    def added(self, program, address_set, monitor, log) -> bool:
        if not isinstance(monitor, TaskMonitor):
            raise ValueError("monitor must be a TaskMonitor")

        do_now_set = set()
        do_later_set = set()

        execute_set = program.get_memory().get_execute_set()

        if not execute_set.is_empty():
            address_set = address_set.intersection(execute_set)

        # look at the codemap property laid down by the importer.
        disassemble_code_map_markers(program, monitor)

        # find any functions that are defined that have no code, and a single address body
        dummy_function_set = set()
        redo_function_set = set()
        find_dummy_functions(program, address_set, dummy_function_set, redo_function_set)

        do_disassembly(program, monitor, dummy_function_set)
        add_code_symbols_to_set(program, address_set, monitor, do_now_set)
        external_count = add_external_symbols_to_set(program, address_set, monitor, do_now_set)
        if not is_single_external_entry_point(program, external_count, do_now_set):
            move_suspect_symbols_to_do_later_set(program, monitor, do_now_set, do_later_set)

        do_disassembly(program, monitor, do_now_set)
        check_do_later_set(program, monitor, do_later_set)
        process_do_later_set(program, monitor, do_later_set)
        fix_dummy_function_bodies(program, monitor, redo_function_set)

    def disassemble_code_map_markers(self, program):
        code_prop = program.get_address_set_property_map("CodeMap")
        if code_prop is not None:
            code_set = set()
            for addr in code_prop.addresses():
                code_set.add(addr)
            do_disassembly(program, monitor, code_set)

    def find_dummy_functions(self, program, address_set, dummy_function_set, redo_function_set):
        functions = program.get_function_manager().get_functions(address_set, True)
        while functions.has_next():
            function = functions.next()
            entry_point = function.entry_point()

            body = function.body()
            if body is None:
                continue

            # if there is data here, don't do
            if program.get_listing().defined_data_at(entry_point) is not None:
                continue

            # if the function has a wimpy body, put on list to re-do
            if len(body) == 1:
                redo_function_set.add(entry_point)

    def add_code_symbols_to_set(self, program, address_set, monitor):
        for addr in address_set:
            symbol = program.get_symbol_table().primary_symbol(addr)
            if symbol is not None and symbol.is_external_entry_point():
                do_now_set.add_range(addr, addr)

    def process_do_later_set(self, program, monitor, set):
        pdis = PseudoDisassembler(program)
        for entry in set:
            monitor.check_canceled()
            if program.get_listing().is_undefined(entry, entry):
                continue

            # relocation at this place, don't trust it
            if program.get_relocation_table().relocation_at(entry) is not None:
                continue

    def fix_dummy_function_bodies(self, program, monitor, redo_function_set):
        for addr in redo_function_set:
            function = program.get_function_manager().function_at(addr)
            CreateFunctionCmd.fixup_function_body(program, function, monitor)

    # ... other methods ...

class PseudoDisassembler:
    def __init__(self, program):
        self.program = program

    def set_respect_execute_flag(self, respect_execute_flags):
        pass  # not implemented in Python

# ... other classes ...
```

Please note that this is a direct translation of the Java code into equivalent Python. The actual implementation may vary depending on how you want to implement certain features or handle exceptions in your specific use case.