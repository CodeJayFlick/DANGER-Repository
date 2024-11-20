class ImportStateCache:
    def __init__(self, program, header):
        self.program = program
        self.symbol_table = program.get_symbol_table()
        self.import_namespace = create_namespace(None, 'PefConstants.IMPORT')
        self.t_vect_namespace = create_namespace(None, 'PefConstants.TVECT')

        loader = header.get_loader()
        libraries = loader.get_imported_libraries()

        for library in libraries:
            name = SymbolUtilities.replace_invalid_chars(library.name, True)
            namespace = create_namespace(self.import_namespace, name)
            self.library_namespace_map[library] = namespace
            self.library_symbols_map[library] = {}

    def dispose(self):
        self.library_namespace_map.clear()
        self.library_symbols_map.clear()

    def get_t_vect_namespace(self):
        return self.t_vect_namespace

    def get_namespace(self, library):
        return self.library_namespace_map.get(library)

    def get_memory_block_for_section(self, section):
        return self.section_map.get(section)

    def set_memory_block_for_section(self, section, block):
        if section in self.section_map:
            raise AssertionError()
        self.section_map[section] = block

    def get_symbol(self, symbol_name, library):
        map = self.library_symbols_map[library]
        return map.get(symbol_name)

    def create_library_symbol(self, library, symbol_name, address):
        namespace = self.get_namespace(library)
        cmd = AddUniqueLabelCmd(address, symbol_name, namespace, 'SourceType.IMPORTED')
        success = cmd.apply_to(self.program)
        symbol = cmd.get_new_symbol()
        map = self.library_symbols_map[library]
        map[symbol_name] = symbol
        return success

    def create_namespace(self, parent, name):
        if (namespace := self.symbol_table.get_namespace(name, parent)) is not None:
            return namespace
        try:
            return self.program.get_symbol_table().create_namespace(parent, name, 'SourceType.IMPORTED')
        except Exception as e:
            return self.program.get_global_namespace()

    def get_toc_address(self):
        return self.toc_address

    def set_toc_address(self, toc_address):
        self.toc_address = toc_address


class AddUniqueLabelCmd:
    pass
