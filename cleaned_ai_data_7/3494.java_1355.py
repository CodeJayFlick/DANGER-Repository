class ClearOptions:
    def __init__(self):
        self.code = True
        self.symbols = True
        self.comments = True
        self.properties = True
        self.functions = True
        self.registers = True
        self.equates = True
        self.user_references = True
        self.analysis_references = True
        self.import_references = True
        self.default_references = True
        self.bookmarks = True

    def __init__(self, code=True, symbols=True, comments=True, properties=True,
                 functions=True, registers=True, equates=True, user_references=True,
                 analysis_references=True, import_references=True, default_references=True,
                 bookmarks=True):
        self.code = code
        self.symbols = symbols
        self.comments = comments
        self.properties = properties
        self.functions = functions
        self.registers = registers
        self.equates = equates
        self.user_references = user_references
        self.analysis_references = analysis_references
        self.import_references = import_references
        self.default_references = default_references
        self.bookmarks = bookmarks

    def set_clear_code(self, code):
        self.code = code

    def set_clear_symbols(self, symbols):
        self.symbols = symbols

    def set_clear_comments(self, comments):
        self.comments = comments

    def set_clear_properties(self, properties):
        self.properties = properties

    def set_clear_functions(self, functions):
        self.functions = functions

    def set_clear_registers(self, registers):
        self.registers = registers

    def set_clear_equates(self, equates):
        self.equates = equates

    def set_clear_user_references(self, user_references):
        self.user_references = user_references

    def set_clear_analysis_references(self, analysis_references):
        self.analysis_references = analysis_references

    def set_clear_import_references(self, import_references):
        self.import_references = import_references

    def set_clear_default_references(self, default_references):
        self.default_references = default_references

    def set_clear_bookmarks(self, bookmarks):
        self.bookmarks = bookmarks

    def clear_code(self):
        return self.code

    def clear_comments(self):
        return self.comments

    def clear_properties(self):
        return self.properties

    def clear_symbols(self):
        return self.symbols

    def clear_functions(self):
        return self.functions

    def clear_registers(self):
        return self.registers

    def clear_equates(self):
        return self.equates

    def clear_user_references(self):
        return self.user_references

    def clear_analysis_references(self):
        return self.analysis_references

    def clear_import_references(self):
        return self.import_references

    def clear_default_references(self):
        return self.default_references

    def clear_bookmarks(self):
        return self.bookmarks

    def get_reference_source_types_to_clear(self):
        source_types_to_clear = set()
        if self.clear_user_references():
            source_types_to_clear.add('USER_DEFINED')
        if self.clear_default_references():
            source_types_to_clear.add('DEFAULT')
        if self.clear_import_references():
            source_types_to_clear.add('IMPORTED')
        if self.clear_analysis_references():
            source_types_to_clear.add('ANALYSIS')
        return source_types_to_clear

    def clear_any(self):
        return (self.code or
                self.symbols or
                self.comments or
                self.properties or
                self.functions or
                self.registers or
                self.equates or
                self.user_references or
                self.analysis_references or
                self.import_references or
                self.default_references or
                self.bookmarks)
