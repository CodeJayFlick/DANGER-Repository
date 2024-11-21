class NoReturnFunctionAnalyzer:
    NAME = "Non-Returning Functions - Known"
    DESCRIPTION = ("Locates known functions by name that generally do not return (exit, abort, etc) "
                   "and sets the \"No Return\" flag.")
    
    OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks"
    OPTION_DESCRIPTION_CREATE_BOOKMARKS = "If checked, an analysis bookmark will be created on each function marked as non-returning."
    DEFAULT_OPTION_CREATE_BOOKMARKS_ENABLED = True

    def __init__(self):
        self.create_bookmarks_enabled = DEFAULT_OPTION_CREATE_BOOKMARKS_ENABLED
        super().__init__(NAME, DESCRIPTION)

    @property
    def can_analyze(self):
        return NonReturningFunctionNames.has_data_files()

    def added(self, program: 'Program', set: 'AddressSetView', monitor: 'TaskMonitor', log: 'MessageLog'):
        try:
            self.load_function_names_if_needed(program)
        except Exception as e:
            log.append_msg(f"Failed to load non-returning function name list: {e.message}")

    def load_function_names_if_needed(self, program):
        if hasattr(self, 'function_names') and self.function_names is not None:
            return

        self.function_names = set()

        files = NonReturningFunctionNames.find_data_files(program)
        for file in files:
            with open(file.get_absolute_path(), 'r') as f:
                reader = BufferedReader(f)
                while True:
                    line = reader.readline()
                    if line is None or line.strip() == '':
                        break
                    elif line[0] == '#':
                        continue

                    start_index = 0
                    while start_index < len(line) and line[start_index].strip() == '_':
                        start_index += 1

                    self.function_names.add(line[start_index:].strip())

    def check_for_associated_external_symbol(self, symbol):
        if symbol.get_address().is_external_address():
            return symbol

        data = program.get_listing().get_defined_data_at(symbol.get_address())
        if data is None or not isinstance(data, Data) and not data.is_pointer():
            return symbol

        references_from = program.get_reference_manager().get_references_from(symbol.get_address())
        for reference in references_from:
            if reference.is_external_reference():
                return program.get_symbol_table().get_primary_symbol(reference.get_to_address())

        return symbol

    def register_options(self, options: 'Options', program: 'Program'):
        options.register_option(NoReturnFunctionAnalyzer.OPTION_NAME_CREATE_BOOKMARKS,
                                self.create_bookmarks_enabled, None,
                                NoReturnFunctionAnalyzer.OPTION_DESCRIPTION_CREATE_BOOKMARKS)

    def options_changed(self, options: 'Options', program: 'Program'):
        self.create_bookmarks_enabled = options.get_boolean(
            NoReturnFunctionAnalyzer.OPTION_NAME_CREATE_BOOKMARKS, 
            self.create_bookmarks_enabled
        )
