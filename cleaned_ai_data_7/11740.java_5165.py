class FlowDestSymbol:
    def __init__(self, location, name, const_space):
        self.const_space = const_space
        super().__init__(location, name)

    @property
    def pattern_expression(self):
        return None  # Cannot be used in pattern expressions

    @property
    def symbol_type(self):
        return 'start_symbol'

    def get_fixed_handle(self, hand, walker):
        ref_addr = walker.get_flow_dest_addr()
        hand.space = self.const_space
        hand.offset_space = None
        hand.offset_offset = ref_addr.get_offset()
        hand.size = ref_addr.get_addr_size()

    @property
    def varnode(self):
        spc = ConstTpl(self.const_space)
        off = ConstTpl(ConstTpl.CONST_TYPE.J_FLOWDEST)
        sz_zero = ConstTpl()
        return VarnodeTpl(self.location, spc, off, sz_zero)

    def print(self, s, pos):
        val = pos.get_flow_dest_addr().get_offset()
        s.append('0x')
        s.print(hex(val))
