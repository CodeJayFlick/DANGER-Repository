class InstructionMetadata:
    def __init__(self, mask_container):
        self.mask_container = mask_container
        self.addr = None
        self.mnemonic = ''
        self.is_instruction = False
        self.mnemonic_masked = False
        self.operands = []

    @property
    def addr(self):
        return self._addr

    @addr.setter
    def addr(self, value):
        self._addr = value

    @property
    def mnemonic(self):
        return self._mnemonic

    @mnemonic.setter
    def mnemonic(self, value):
        self._mnemonic = value

    @property
    def is_instruction(self):
        return self._is_instruction

    @is_instruction.setter
    def is_instruction(self, value):
        self._is_instruction = value

    @property
    def operands(self):
        return self._operands

    @operands.setter
    def operands(self, value):
        self._operands = value

    @property
    def mnemonic_masked(self):
        return self._mnemonic_masked

    @mnemonic_masked.setter
    def mnemonic_masked(self, value):
        self._mnemonic_masked = value


class MaskContainer:
    pass  # This class is not defined in the original Java code. It seems to be a custom class.
