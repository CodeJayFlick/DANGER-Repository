class IsolatedFailPluginB:
    ERROR_MSG = "Isolated Fail Plugin B error message"

    def __init__(self):
        pass

    def init(self):
        raise RuntimeError(self.ERROR_MSG)
