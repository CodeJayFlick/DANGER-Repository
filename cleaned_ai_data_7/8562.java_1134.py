class PdbApplicatorControl:
    ALL = ("Process All",)
    DATA_TYPES_ONLY = ("Data Types Only",)
    PUBLIC_SYMBOLS_ONLY = ("Public Symbols Only",)

    def __str__(self):
        return self.label

    def __init__(self, label):
        self.label = label
