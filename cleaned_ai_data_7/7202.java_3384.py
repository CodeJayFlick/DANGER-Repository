class OatQuickMethodHeader:
    def __init__(self):
        pass

    def get_code_size(self):
        raise NotImplementedError("Subclasses must implement this method")
