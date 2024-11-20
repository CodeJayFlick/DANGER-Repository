class MDObjectReserved:
    def __init__(self, dmang):
        super().__init__(dmang)

    def insert(self, builder):
        super().insert(builder)

    def parse_internal(self):
        # Go to end of string.
        self.dmang.increment(len(self.dmang.mangled_symbol) - self.dmang.index)


class MDMang:
    pass


def parse_digits(dmang):
    ret = ""
    while dmang.peek() >= '0' and dmang.peek() <= '9':
        ret += dmang.get_and_increment()
    return ret
