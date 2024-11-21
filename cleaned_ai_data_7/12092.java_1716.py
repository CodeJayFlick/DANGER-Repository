class LibrarySymbol:
    def __init__(self):
        self.library = None

    def set_symbol_manager(self, symbol_mgr: 'SymbolManager', cache: 'DBObjectCache[SymbolDB]', address: 'Address', record: 'DBRecord'):
        super().__init__(symbol_mgr, cache, address, record)

    def set_name(self, new_name: str, source: 'SourceType') -> None:
        old_name = self.get_name()
        if old_name == Library.UNKNOWN:
            print("Unable to change name of " + Library.UNKNOWN + " Library")
            return
        super().set_name(new_name, source)
        if old_name != self.get_name():
            symbol_mgr.program.set_obj_changed(ChangeManager.DOCR_EXTERNAL_NAME_CHANGED, None, None, old_name, new_name)

    def set_name_and_namespace(self, new_name: str, namespace: 'Namespace', source: 'SourceType') -> None:
        old_name = self.get_name()
        super().set_name_and_namespace(new_name, namespace, source)
        if old_name != self.get_name():
            symbol_mgr.program.set_obj_changed(ChangeManager.DOCR_EXTERNAL_NAME_CHANGED, None, None, old_name, new_name)

    def set_symbol_string_data(self, new_path: str) -> None:
        old_path = self.get_symbol_string_data()
        super().set_symbol_string_data(new_path)
        if old_path != self.get_symbol_string_data():
            symbol_mgr.program.set_obj_changed(ChangeManager.DOCR_EXTERNAL_PATH_CHANGED, self.get_name(), old_path, new_path)

    def get_symbol_type(self) -> 'SymbolType':
        return SymbolType.LIBRARY

    def is_external(self) -> bool:
        return True

    def get_object(self) -> object:
        if not hasattr(self, "library"):
            self.library = LibraryDB(self, symbol_mgr.program.get_namespace_manager())
        return self.library

    def is_primary(self) -> bool:
        return True

    def get_program_location(self):
        # TODO Auto-generated method stub
        return None

    def is_valid_parent(self, parent: 'Namespace') -> bool:
        return SymbolType.LIBRARY.is_valid_parent(symbol_mgr.program, parent, self.get_address(), self.is_external())
