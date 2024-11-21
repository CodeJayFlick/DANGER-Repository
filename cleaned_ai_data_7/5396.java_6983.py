class LibraryExportedSymbol:
    def __init__(self, lib_name, memsize, ordinal, symbol_name,
                 forward_library_name, forward_symbol_name, purge, no_return, comment):
        self.lib_name = lib_name
        self.memsize = memsize
        self.ordinal = ordinal
        self.symbol_name = symbol_name
        self.forward_library_name = forward_library_name
        self.forward_symbol_name = forward_symbol_name
        self.purge = purge
        self.no_return = no_return
        self.comment = comment

    def get_lib_name(self):
        return self.lib_name

    def get_ordinal(self):
        return self.ordinal

    def get_name(self):
        return self.symbol_name

    def get_purge(self):
        if self.is_forward_entry() and self.purge == -1:
            self.process_forwarded_entry()
        elif self.purge == -2:
            self.purge = -1
        return self.purge

    def has_no_return(self):
        if self.is_forward_entry() and self.purge == -1:
            self.process_forwarded_entry()
        elif self.purge == -2:
            self.purge = -1
        return self.no_return

    def process_forwarded_entry(self):
        self.purge = -2
        lib_symbol_table = LibraryLookupTable.get_symbol_table(self.forward_library_name, self.memsize)
        if lib_symbol_table is None:
            return
        lib_sym = lib_symbol_table.get_symbol(self.forward_symbol_name)
        if lib_sym is None:
            return
        self.purge = lib_sym.get_purge()
        if self.purge != -1:
            self.no_return = lib_sym.has_no_return()

    def get_comment(self):
        return self.comment

    def is_forward_entry(self):
        return self.forward_library_name is not None

    def get_forward_library_name(self):
        return self.forward_library_name

    def get_forward_symbol_name(self):
        return self.forward_symbol_name

    def set_name(self, name):
        self.symbol_name = name
