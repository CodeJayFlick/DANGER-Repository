class ContextChange:
    def __init__(self):
        pass

    def validate(self):
        raise NotImplementedError("Abstract method must be implemented")

    def save_xml(self, s):
        raise NotImplementedError("Abstract method must be implemented")

    def restore_xml(self, el, trans):
        raise NotImplementedError("Abstract method must be implemented")

    def apply(self, pos):
        raise NotImplementedError("Abstract method must be implemented")

    def dispose(self):
        pass
