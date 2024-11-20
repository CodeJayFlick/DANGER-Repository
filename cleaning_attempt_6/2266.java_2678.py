class TestTargetStackFrameHasRegisterBank:
    def __init__(self, parent, level, pc):
        self.parent = parent
        self.level = level
        self.pc = pc
        self.bank = TestTargetRegisterBankInFrame(self)

    @property
    def bank(self):
        return self._bank

    @bank.setter
    def bank(self, value):
        self._bank = value

    def set_from_frame(self, frame):
        if isinstance(frame, TestTargetStackFrameHasRegisterBank):
            self.pc = frame.pc
            self.bank.set_from_bank(frame.bank)

    def set_pc(self, pc):
        self.pc = pc

class TestTargetRegisterBankInFrame:
    def __init__(self, parent):
        self.parent = parent

    def set_from_bank(self, bank):
        # Implement the logic to set from a bank
        pass

# Example usage:

parent_stack = "Parent Stack"
level = 1
pc = "0x12345678"

test_target_frame = TestTargetStackFrameHasRegisterBank(parent_stack, level, pc)

print(test_target_frame.pc)  # Output: 0x12345678
print(test_target_frame.bank)  # Output: An instance of TestTargetRegisterBankInFrame

# Set the PC and bank from another frame:
another_frame = TestTargetStackFrameHasRegisterBank("Another Stack", level, "0x98765432")
test_target_frame.set_from_frame(another_frame)

print(test_target_frame.pc)  # Output: 0x98765432
