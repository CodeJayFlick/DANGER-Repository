class ContextSymbol:
    def __init__(self, location):
        pass  # For use with restore_xml

    @property
    def varnode(self):
        return self._vn

    @varnode.setter
    def varnode(self, value):
        self._vn = value

    @property
    def low(self):
        return self._low

    @low.setter
    def low(self, value):
        self._low = value

    @property
    def high(self):
        return self._high

    @high.setter
    def high(self, value):
        self._high = value

    @property
    def flow(self):
        return self._flow

    @flow.setter
    def flow(self, value):
        self._flow = value

    def __init__(self, location, nm, pate, v, l, h, f):
        pass  # For use with restore_xml

    def get_type(self):
        return "context_symbol"

    def save_xml(self, s):
        s.write("<context_sym")
        self.save_sleigh_symbol_xml_header(s)
        s.write(" varnode=\"0x" + str(hex(vn.id)) + "\"")
        s.write(" low=\"" + str(low) + "\"")
        s.write(" high=\"" + str(high) + "\" flow=\"" + str(flow))
        s.write("/>\n")
        self.patval.save_xml(s)

    def save_xml_header(self, s):
        s.write("<context_sym_head")
        self.save_sleigh_symbol_xml_header(s)
        s.write("/>\n")

    def restore_xml(self, el, trans):
        super().restore_xml(el, trans)
        id = int(el.get("varnode"), 16)
        vn = (VarnodeSymbol)trans.find_symbol(id)
        low = int(el.get("low"))
        high = int(el.get("high"))

class VarnodeSymbol:
    def __init__(self):
        pass

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

# Note: This is a simplified translation and might not work as-is in your Python program.
