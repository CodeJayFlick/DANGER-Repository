Here is the translation of the Java code into Python:

```Python
class PdbApplicatorOptions:
    def __init__(self):
        self.set_defaults()

    def set_defaults(self):
        self.apply_code_scope_block_comments = False
        self.apply_instruction_labels = False
        self.control = "ALL"
        self.remap_address_using_existing_public_mangled_symbols = False
        self.allow_demote_primary_mangled_symbols = True
        self.apply_function_variables = False
        self.composite_layout = ObjectOrientedClassLayout.MEMBERS_ONLY

    def register_analyzer_options(self, options):
        if self.developer_mode or self.control == "ALL":
            options.register_option("Control", self.get_processing_control(), None,
                                     "Applicator processing control.")
        # PdbApplicatorOptions
        if self.developer_mode:
            options.register_option(
                "Apply Code Scope Block Comments",
                self.apply_code_scope_block_comments, None,
                "If checked, pre/post-comments will be applied when code scope blocks are specified."
            )
            options.register_option(
                "Apply Instruction Labels", self.apply_instruction_labels, None,
                "If checked, labels associated with instructions will be applied."
            )
            options.register_option(
                "Address Remap Using Existing Symbols",
                self.remap_address_using_existing_public_mangled_symbols, None,
                "If checked, attempts to remap address to those matching existing public symbols."
            )
            options.register_option(
                "Allow Demote Mangled Symbol from Primary", 
                self.allow_demote_primary_mangled_symbols, None,
                "Allows a mangled symbol to be demoted from primary if a possibly better data type can be laid down with a nonmangled symbol."
            )
            options.register_option(
                "Apply Function Variables",
                self.apply_function_variables, None,
                "If checked, attempts to apply function parameters and local variables for program functions."
            )
            options.register_option(
                "Composite Layout Choice", 
                self.composite_layout, None,
                "Legacy layout like original PDB Analyzer. Warning: other choices have no compatibility guarantee with future Ghidra releases or minor PDB Analyzer changes"
            )

    def load_analyzer_options(self, options):
        if self.developer_mode or self.control == "ALL":
            self.control = options.get_enum("Control", self.control)
        # PdbApplicatorOptions
        if self.developer_mode:
            self.apply_code_scope_block_comments = options.get_bool(
                "Apply Code Scope Block Comments",
                self.apply_code_scope_block_comments
            )
            self.apply_instruction_labels = options.get_bool(
                "Apply Instruction Labels", 
                self.apply_instruction_labels
            )
            self.remap_address_using_existing_public_mangled_symbols = options.get_bool(
                "Address Remap Using Existing Symbols",
                self.remap_address_using_existing_public_mangled_symbols
            )
            self.allow_demote_primary_mangled_symbols = options.get_bool(
                "Allow Demote Mangled Symbol from Primary", 
                self.allow_demote_primary_mangled_symbols
            )
            self.apply_function_variables = options.get_bool(
                "Apply Function Variables",
                self.apply_function_variables
            )
            self.composite_layout = options.get_enum("Composite Layout Choice", self.composite_layout)

    def set_processing_control(self, control):
        self.control = control

    def get_processing_control(self):
        return self.control

    # ... and so on for the rest of the methods ...

class ObjectOrientedClassLayout:
    MEMBERS_ONLY = "MEMBERS ONLY"
    BASIC_SIMPLE_COMPLEX = "BASIC SIMPLE COMPLEX"
    SIMPLEX = "SIMPLEX"
    COMPLEX = "COMPLEX"

# Usage
options = PdbApplicatorOptions()
options.set_defaults()

# ... and so on for the rest of your code ...
```

Please note that Python does not have direct equivalent to Java's `abstract` keyword. Also, Python has no concept of static variables like in Java.