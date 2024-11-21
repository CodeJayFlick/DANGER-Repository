class GlobalRegisterSymbol:
    def __init__(self, mgr, cache, addr, record):
        super().__init__(mgr, cache, addr, record)

    @property
    def symbol_type(self):
        return 'GLOBAL_VAR'

    def is_external(self):
        return False

    def get_object(self):
        reg = self.symbol_mgr.get_program().get_register(self.address)
        return reg

    @property
    def primary(self):
        return True

    def get_program_location(self):
        return None

    def valid_parent(self, parent):
        return SymbolType('GLOBAL_VAR').valid_parent(self.symbol_mgr.get_program(), parent, self.address, False)

class SymbolDB:
    pass

class DBObjectCache:
    pass

class Address:
    pass

class Register:
    pass

class Namespace:
    pass
