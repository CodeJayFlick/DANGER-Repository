class RecorderSimpleRegisterSet:
    def __init__(self, recorder):
        self.recorder = recorder
        self.bank = None  # initialize bank as None

    def update_registers(self, new_regs, old_regs):
        self.bank = new_regs
