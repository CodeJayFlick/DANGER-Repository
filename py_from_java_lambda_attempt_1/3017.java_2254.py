Here is the translation of the given Java code into equivalent Python:

```Python
class DWARFExtractorScript:
    def run(self):
        if not self.is_dwarf():
            print("Unable to find DWARF information, aborting")
            return
        
        import_options = {'import_limit_die_count': int('inf')}
        
        try:
            dwarf_prog = DWARFProgram(current_program, **import_options)
            dtms = BuiltInDataTypeManager()
            dp = DWARFParser(dwarf_prog, dtms)
            import_summary = dp.parse()
            import_summary.log_summary_results()
        except Exception as e:
            print(f"An error occurred: {e}")

    def is_dwarf(self):
        return current_program.is_dwarf()

class BuiltInDataTypeManager:
    @staticmethod
    def get_data_type_manager():
        pass

class DWARFProgram:
    @classmethod
    def is_dwarf(cls, program):
        # implement this method to check if the given program contains dwarf information
        pass

    @classmethod
    def from_program(cls, program, import_options=None):
        return cls(program, **import_options)

class DWARFParser:
    def __init__(self, dwarf_prog, dtms):
        self.dwarf_prog = dwarf_prog
        self.dtms = dtms

    def parse(self):
        # implement this method to parse the dwarf information and generate a summary
        pass

# usage example
script = DWARFExtractorScript()
script.run()
```

Please note that you would need to define the classes `DWARFProgram`, `BuiltInDataTypeManager` and `DWARFParser` with their respective methods. The code above is just an equivalent translation of your Java code into Python, it's not a complete working script as some parts are missing (like method implementations).