Here is the translation of the Java code into Python:

```Python
class DWARFImportSummary:
    def __init__(self):
        self.data_type_elapsed_ms = 0
        self.funcs_elapsed_ms = 0
        self.total_elapsed_ms = 0

        self.data_types_added = 0
        self.funcs_added = 0
        self.funcs_updated = 0
        self.func_signatures_added = 0
        self.global_vars_added = 0

        self.unknown_registers_encountered = set()
        self.relocation_error_var_defs = set()
        self.var_fit_error = 0
        self.var_dynamic_register_error = 0
        self.var_dwarf_expression_value = 0
        self.expr_read_error = 0

    def log_summary_results(self):
        if self.total_elapsed_ms > 0:
            print(f"DWARF import - total elapsed: {self.total_elapsed_ms}ms")

        if self.data_type_elapsed_ms > 0:
            print(f"DWARF data type import - elapsed: {self.data_type_elapsed_ms}ms")

        if self.funcs_elapsed_ms > 0:
            print(f"DWARF func & symbol import - elapsed: {self.funcs_elapsed_ms}ms")

        if self.data_types_added > 0:
            print(f"DWARF types imported: {self.data_types_added}")

        if self.funcs_added > 0:
            print(f"DWARF funcs added: {self.funcs_added}")

        if self.func_signatures_added > 0:
            print(f"DWARF function signatures added: {self.func_signatures_added}")

        if len(self.type_remappings) > 0:
            print("DWARF data type remappings (DWARF data type definitions that changed meaning in different compile units):")
            for s in self.type_remappings:
                print(s)
            if len(self.type_remappings) > 1000:
                print(f"...omitting {len(self.type_remappings)-1000} additional type remapping warnings.")

        if len(self.relocation_error_var_defs) > 0:
            print("DWARF static variables with missing address info:")
            for var_def in self.relocation_error_var_defs:
                print(var_def)

        if self.var_fit_error > 0:
            print(f"DWARF variable definitions that failed because the data type was too large for the defined register location: {self.var_fit_error}")

        if self.var_dynamic_register_error > 0:
            print(f"DWARF variable definitions that failed because they depended on the dynamic value of a register: {self.var_dynamic_register_error}")

        if self.var_dwarf_expression_value > 0:
            print(f"DWARF variable definitions that failed because they are computed pseudo variables: {self.var_dwarf_expression_value}")

        if self.expr_read_error > 0:
            print(f"DWARF expression failed to read: {self.expr_read_error}")
```

Note that Python does not have direct equivalents for Java's `Msg` class and its methods. In this translation, I replaced the calls to `Msg.info()` with simple print statements, as they seem to be used primarily for logging purposes.