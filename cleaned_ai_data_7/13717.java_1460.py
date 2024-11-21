class Modem:
    def __init__(self):
        pass

    def accept(self, modem_visitor):
        raise NotImplementedError("Method 'accept' must be implemented by subclass")
