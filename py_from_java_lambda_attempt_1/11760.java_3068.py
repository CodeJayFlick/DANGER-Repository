Here is the translation of the given Java code into Python:

```Python
class ValueMapSymbol:
    def __init__(self, location):
        self.location = location
        self.valuetable = []
        self.tableisfilled = False

    def __init__(self, location, nm, pv, vt):
        super().__init__(location)
        self.name = nm
        self.pattern_value = pv
        self.valuetable = list(vt)
        self.check_table_fill()

    @property
    def type(self):
        return "valuemap_symbol"

    def check_table_fill(self):
        min_val = self.pattern_value.min_value()
        max_val = self.pattern_value.max_value()
        self.tableisfilled = (min_val >= 0) and (max_val < len(self.valuetable))
        for i in range(len(self.valuetable)):
            if self.valuetable[i] == 0xBADBEEF:
                self.tableisfilled = False
                break

    def resolve(self, pos):
        if not self.tableisfilled:
            ind = int(self.pattern_value.get_value(pos))
            if (ind >= len(self.valuetable)) or (ind < 0) or (self.valuetable[ind] == 0xBADBEEF):
                raise BadDataError("No corresponding entry in nametable <", self.name, "> index=", ind)
        return None

    def get_fixed_handle(self, hand, pos):
        ind = int(self.pattern_value.get_value(pos))
        # The resolve routine has checked that -ind- must be a valid index
        hand.space = pos.const_space
        hand.offset_space = None  # Not a dynamic value
        hand.offset_offset = self.valuetable[ind]
        hand.size = 0  # Cannot provide size

    def print(self, s, pos):
        ind = int(self.pattern_value.get_value(pos))
        val = self.valuetable[ind]
        if val >= 0:
            s.append("0x")
            s.append(hex(val)[2:])
        else:
            s.append("-0x")
            s.append(hex(-val)[2:])

    def save_xml(self, s):
        s.write("<valuemap_ym>\n")
        self.save_sleigh_symbol_xml_header(s)
        s.write(str(self.pattern_value))
        for i in range(len(self.valuetable)):
            s.write("<valuetab val=\"{}\"/>\n".format(hex(self.valuetable[i])[2:]))
        s.write("</valuemap_ym>\n")

    def save_xml_header(self, s):
        s.write("<valuemap_ym_head>\n")
        self.save_sleigh_symbol_xml_header(s)
        s.write("/>\n")

    def restore_xml(self, el, trans):
        list = el.getchildren()
        iterator = iter(list)
        element = next(iterator)
        self.pattern_value = PatternExpression.restore_expression(element, trans).value
        while True:
            try:
                child = next(iterator)
                value = XmlUtils.decode_unknown_long(child.get("val"))
                self.valuetable.append(value)
            except StopIteration:
                break
        self.check_table_fill()
```

Please note that this translation is not a direct conversion, but rather an equivalent Python code. The original Java code may have some specific requirements or constraints that are not directly applicable to the translated Python code.