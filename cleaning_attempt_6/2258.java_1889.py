class TestTargetRegisterBankInFrame:
    def __init__(self, parent):
        super().__init__(parent, "RegisterBank", "RegisterBank", parent.parent.parent.parent.parent.regs)

    def get_thread(self):
        return self.parent.parent.parent

    async def write_registers_named(self, values: dict) -> None:
        await self.write_regs(values, lambda x: self.parent.set_pc(x))
