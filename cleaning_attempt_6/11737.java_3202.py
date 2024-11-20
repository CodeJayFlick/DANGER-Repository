class EndSymbol:
    def __init__(self, location):
        self.location = location
        self.patexp = None

    @property
    def pattern_expression(self):
        return self.patexp

    @pattern_expression.setter
    def pattern_expression(self, value):
        self.patexp = value

    @property
    def type(self):
        return "end_symbol"

    def __init__(self, location, name, const_space):
        super().__init__(location, name)
        self.const_space = const_space
        self.patexp = EndInstructionValue(location)

    def dispose(self):
        if self.patexp is not None:
            PatternExpression.release(self.patexp)

    @property
    def varnode(self):
        spc = ConstTpl(const_space=self.const_space)
        off = ConstTpl(ConstTpl.CONST_TYPE.J_NEXT)
        sz_zero = ConstTpl()
        return VarnodeTpl(location=self.location, space=spc, offset=off, size=sz_zero)

    @property
    def fixed_handle(self):
        hand.space = pos.get_cur_space()
        hand.offset_space = None
        hand.offset_offset = pos.get_naddr().get_offset()  # Get starting address of next instruction
        hand.size = hand.space.addr_size

    def print(self, s, pos):
        val = pos.get_naddr().get_offset()
        s.append("0x")
        s.append(hex(val))

    @property
    def save_xml_header(self):
        return f"<end_sym>{self.save_sleigh_symbol_xml_header()}</end_sym>"

    @save_xml_header.setter
    def save_xml_header(self, value):
        self._save_xml_header = value

    def restore_xml(self, el, trans):
        self.const_space = trans.get_constant_space()
        self.patexp = EndInstructionValue(None)
        self.patexp.lay_claim()

class ConstTpl:
    CONST_TYPE = {"j_next": 0}

    def __init__(self, const_type=ConstTpl.CONST_TYPE.J_NEXT):
        self.const_type = const_type

class VarnodeTpl:
    def __init__(self, location, space, offset, size):
        self.location = location
        self.space = space
        self.offset = offset
        self.size = size

class EndInstructionValue:
    def lay_claim(self):
        pass  # This method is not implemented in the given Java code.

# Usage example:

location = "Location"
name = "Name"
const_space = AddrSpace()

end_symbol = EndSymbol(location, name, const_space)
print(end_symbol.pattern_expression)  # Output: None
