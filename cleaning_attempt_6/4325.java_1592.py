class StringsAnalyzer:
    def __init__(self):
        self.name = "ASCII Strings"
        self.description = "This analyzer searches for valid ASCII strings and automatically creates them in the binary."
        
        # Option Names
        self.model_file_option_name = "Model File"
        self.model_file_option_description = "Any model files for this analyzer should be located in the Ghidra/Features/Base/data/stringngrams directory and end in '.sng'."
        
        self.force_model_reload_option_name = "Force Model Reload"
        self.force_model_reload_option_description = "When checked, forces reload of model files every time the analyzer is run. When unchecked, model files will only be reloaded when Ghidra is restarted or when model file option name is changed."
        
        # ... (other options)

    def set_create_string_over_existing_string(self, b):
        self.allow_string_creation_with_existring_substring = b

    def set_create_string_over_existing_reference(self, b):
        self.allow_string_creation_with_offcut_references = b

    def set_min_string_length(self, length):
        self.min_string_length = length

    def set_require_null_termination(self, b):
        self.require_null_end = b

    def set_string_start_alignment(self, alignment):
        if alignment in [1, 2, 4]:
            self.start_alignment = alignment
        else:
            print("Invalid string start alignment. Setting to default of 1.")

    # ... (other setter methods)

    def register_options(self, options, program):
        options.register_option(self.model_file_option_name, "StringModel.sng", None,
                                 self.model_file_option_description)
        
        # ... (register other options)

    def options_changed(self, options, program):
        self.model_name = options.get_string(self.model_file_option_name, "StringModel.sng")
        self.set_trigram_filename(self.model_name)

        self.min_string_length = options.get_int("Minimum String Length", 5)
        
        # ... (set other option values)

    def set_trigram_filename(self, name):
        if not name.endswith(".sng"):
            self.trigram_file = f"{name}.sng"
        else:
            self.trigram_file = name

    def find_strings(self, program, address_set_view, minimum_string_length, align_val,
                     require_null_termination, include_all_char_widths, monitor):
        found_string_callback = lambda x: self.create_string_if_valid(x, program, address_set_view, monitor)

        searcher = StringSearcher(program, minimum_string_length, align_val,
                                  include_all_char_widths, require_null_termination)
        
        searcher.search(address_set_view, found_string_callback, True, monitor)

    def create_string_if_valid(self, found_string, program, address_set_view, monitor):
        if monitor.is_cancelled():
            return

        candidate = StringAndScores(found_string.get_string(program), is_lowercase_model=True)

        # ... (rest of the method remains same as in Java)
