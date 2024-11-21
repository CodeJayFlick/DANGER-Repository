class GdbCommandRunningEvent:
    def __init__(self, tail=None):
        if tail is None:
            self.tail = GdbMiFieldList()
        else:
            try:
                super().__init__(tail)
            except Exception as e:
                raise GdbParseError from e

    @property
    def state(self) -> 'GdbState':
        return None  # Let running cause change, as it has more info.
