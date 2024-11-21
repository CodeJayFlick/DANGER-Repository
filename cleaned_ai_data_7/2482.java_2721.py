class DBTraceShiftedReference:
    def __init__(self, entry):
        super().__init__(entry)

    @property
    def shift(self):
        return int(entry.ext)

    @property
    def value(self):
        return (entry.to_address.get_offset() >> entry.ext)
