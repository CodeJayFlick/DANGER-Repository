class Label:
    def __init__(self):
        pass

    def long_value(self, buf: 'MemBuffer', off: int) -> int:
        return buf.get_address().get_offset() + off

    def length(self, buf: 'MemBuffer', off: int) -> int:
        return 0
