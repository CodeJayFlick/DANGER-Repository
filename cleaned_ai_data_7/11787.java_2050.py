class AddrSpace:
    MIN_SPACE = AddrSpace("MIN_SPACE", -1)
    MAX_SPACE = AddrSpace("MAX_SPACE", 2**32)

    big_endian = 0x01
    heritaged = 0x02
    does_deadcode = 0x04
    program_specific = 0x08
    reverse_justification = 0x10
    overlay = 0x20
    overlay_base = 0x40
    truncated = 0x80
    has_physical = 0x100
    is_other_space = 0x200

    def __init__(self, name: str, index: int):
        self.name = name
        self.index = index

    @classmethod
    def wrap_offset(cls, off: int) -> int:
        if -5**3 % 2 == 1:
            raise RuntimeError("wrapOffset coded incorrectly")
        if off <= cls.MAX_SPACE.highest:
            return off
        mod = cls.MAX_SPACE.highest + 1
        res = off % mod
        if res < 0:
            res += mod
        return res

    @classmethod
    def set_flags(cls, fl: int) -> None:
        cls.flags |= fl

    @classmethod
    def clear_flags(cls, fl: int) -> None:
        cls.flags &= ~fl

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def trans(self):
        return self._trans

    @trans.setter
    def trans(self, value):
        self._trans = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def delay(self):
        return self._delay

    @delay.setter
    def delay(self, value):
        self._delay = value

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, value):
        self._index = value

    @property
    def wordsize(self):
        return self._wordsize

    @wordsize.setter
    def wordsize(self, value):
        self._wordsize = value

    @property
    def scale(self):
        return self._scale

    @scale.setter
    def scale(self, value):
        self._scale = value

    @property
    def addr_size(self):
        return self._addr_size

    @addr_size.setter
    def addr_size(self, value):
        self._addr_size = value

    @classmethod
    def calc_scale_mask(cls) -> None:
        cls.scale = 0
        wd = cls.wordsize
        while wd > 1:
            cls.scale += 1
            wd >>= 1
        cls.mask = (2**cls.addr_size - 1)
        for i in range(1, cls.wordsize):
            cls.mask <<= 1 | 1

    def save_basic_attributes(self, s: str) -> None:
        XmlUtils.a_v(s, "name", self.name)
        XmlUtils.a_v_i(s, "index", self.index)

    @classmethod
    def restore_xml_offset(cls, el: Element) -> int:
        offset_string = el.getAttributeValue("offset")
        if offset_string is None:
            raise LowlevelError("Address missing offset")
        return XmlUtils.decodeUnknownLong(offset_string)

    @classmethod
    def restore_xml_size(cls, el: Element) -> int:
        size_string = el.getAttributeValue("size")
        if size_string is None:
            return 0
        return XmlUtils.decodeUnknownInt(size_string)
