class MDCoinType:
    def __init__(self):
        pass

    @property
    def type_name(self) -> str:
        return "cointerface"


# Note: This class does not have a direct equivalent in Python, as it seems to be related to some sort of data mangling.
class MDCoinTypeComplex(MDCoinType):
    def __init__(self, dmang, start_index_offset):
        super().__init__()
