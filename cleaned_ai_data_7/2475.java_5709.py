class DBTraceOffsetReference:
    def __init__(self, ent):
        super().__init__(ent)

    @property
    def offset(self):
        return ent.ext

    @property
    def base_address(self):
        return Address(ent.to_address) - ent.ext
