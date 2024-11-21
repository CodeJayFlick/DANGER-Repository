class OtherSpace:
    def __init__(self, t, nm=None, ind=0):
        super().__init__(t, 'IPTR_PROCESSOR', nm, 8, 1, ind, 0, 0)
        self.clear_flags('heritaged')
        self.set_flags('is_otherspace')

    @classmethod
    def from_translate(cls, t):
        return cls(t)

    def print_raw(self, s, offset):
        s.write("0x")
        s.write(hex(offset))
        return self.get_trans().get_default_size()

    def save_xml(self, s):
        s.write("<space_other")
        self.save_basic_attributes(s)
        s.write("/>")
