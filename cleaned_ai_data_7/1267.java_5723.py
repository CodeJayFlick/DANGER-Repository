class GdbBreakpointDisp:
    KEEP = ("keep",)
    DEL = ("del",)
    OTHER = ("<OTHER>",)

    @classmethod
    def from_str(cls, string):
        try:
            return next((value for name, value in vars(cls).values() if str(value) == string.upper()), cls.OTHER)
        except TypeError:
            return cls.OTHER

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    def get_name(self):
        return self.name
