class WrappedDbgModel:
    def __init__(self):
        self.client = None
        self.util = None
        self.map = {}

    def getDebugValue(self, register):
        if value instanceof Short:
            return DebugInt16Value(value)
        elif value instanceof Integer:
            return DebugInt32Value(value)
        else:
            return DebugInvalid()

    def setRegisterDescription(self, i):
        return client.getRegisters().getDescription(i)

    def getNumberRegisters(self):
        return client.getRegisters().getNumberRegisters()

    def getRegisterByIndex(self, index):
        return client.getRegisters().getRegister(index)

    def getCurrentSystemId(self):
        return client.getDbgModelNative().getCurrentSession()
