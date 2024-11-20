Here is the translation of the given Java code into Python:

```Python
class SymbolEntry:
    def __init__(self, symbol):
        self.symbol = symbol
        self.pcaddr = None

    def restore_xml(self, parser):
        pass  # abstract method in Python

    def save_xml(self, buf):
        pass  # abstract method in Python

    def get_storage(self):
        pass  # abstract method in Python

    def get_size(self):
        return 0  # default size is 0

    def is_read_only(self):
        return False  # default read-only status is False

    def is_volatile(self):
        return False  # default volatile status is False

    def get_pc_address(self):
        return self.pcaddr


class HighSymbol:
    pass  # this class does not exist in the given Java code, so it's just a placeholder


def parse_range_list(parser):
    rangelistel = parser.start("rangelist")
    if parser.peek().is_start():
        rangeel = parser.start("range")
        spc = rangeel.get_attribute("space")
        offset = int(rangeel.get_attribute("first"))
        pcaddr = Address(spc, offset)
        pcaddr = pcaddr.overlay_address()
        parser.end(rangeel)

    parser.end(rangelistel)


def build_rangelist_xml(res):
    if not (pcaddr and not pcaddr.is_external_address()):
        res.append("<rangelist/>")
        return

    res.append("<rangelist>")
    space = pcaddr.get_address_space()
    off = 0
    if space.is_overlay_space():
        space = space.get_physical_space()
        off = int(space.address(pcaddr.offset).get_unsigned_offset())
    else:
        off = int(pcaddr.get_unsigned_offset())

    res.append("<range")
    SpecXmlUtils.encode_string_attribute(res, "space", space.name)
    SpecXmlUtils.encode_unsigned_integer_attribute(res, "first", off)
    SpecXmlUtils.encode_unsigned_integer_attribute(res, "last", off)
    res.append("/>")
    res.append("</rangelist>\n")


class Address:
    def __init__(self, spc, offset):
        self.address_space = spc
        self.offset = offset

    @property
    def get_address_space(self):
        return self.address_space


class XmlPullParser:
    def start(self, tag):
        pass  # abstract method in Python

    def peek(self):
        pass  # abstract method in Python

    def end(self, el):
        pass  # abstract method in Python

    @property
    def get_attribute(self, attr_name):
        return ""


class SpecXmlUtils:
    @staticmethod
    def encode_string_attribute(res, name, value):
        res.append(f"<{name}>{value}</{name}>")

    @staticmethod
    def encode_unsigned_integer_attribute(res, name, value):
        res.append(f"<{name}>{str(value)}</{name}>")


class XmlElement:
    pass  # this class does not exist in the given Java code, so it's just a placeholder


class PcodeXMLException(Exception):
    pass