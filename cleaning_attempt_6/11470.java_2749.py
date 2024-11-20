class SledException(Exception):
    def __init__(self, e=None):
        if e:
            super().__init__(e.getMessage())
        else:
            super().__init__()

    @classmethod
    def from_string(cls, message):
        return cls(message)
