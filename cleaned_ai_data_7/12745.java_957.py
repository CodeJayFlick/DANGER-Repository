class CodeUnitContainer:
    def __init__(self, code_unit):
        self.code_unit = code_unit
        self.mnemonic = code_unit.get_mnemonic_string()
        self.arity = code_unit.get_num_operands()

    def __str__(self):
        return f"{self.code_unit.__str__()} @ {self.code_unit.get_address_string(False, True)}"

    def get_code_unit(self):
        return self.code_unit

    def get_mnemonic(self):
        return self.mnemonic

    def get_arity(self):
        return self.arity
