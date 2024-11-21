class LldbListStackFrameRegistersCommand:
    def __init__(self, manager, bank):
        self.manager = manager
        self.bank = bank
        self.result = {}

    def complete(self, pending):
        return self.result

    def invoke(self):
        self.result = {}
        n = len(self.bank.children)
        for i in range(n):
            child = self.bank.GetChildAtIndex(i, True)
            self.result[DebugClient.getId(child)] = child
