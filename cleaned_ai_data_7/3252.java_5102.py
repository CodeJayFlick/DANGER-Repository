class AssociateSymbolCmd:
    def __init__(self, ref, symbol_name=None, scope=None):
        self.ref = ref
        if scope:
            self.symbol_name = scope.get_symbol().get_name()
        else:
            self.symbol_name = symbol_name

    @staticmethod
    def create_associate_symbol_cmd(ref, symbol_name, scope=None):
        return AssociateSymbolCmd(ref, symbol_name, scope)

    def apply_to(self, obj):
        sym_table = (obj).get_symbol_table()
        ref_mgr = (obj).get_reference_manager()

        s = sym_table.get_symbol(self.symbol_name, self.ref.get_to_address(), None)
        if not s:
            return False
        ref_mgr.set_association(s, self.ref)
        return True

    def get_status_msg(self):
        return self.msg

    @property
    def name(self):
        return "Set Symbol Reference Association"
