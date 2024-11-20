Here is the translation of the Java code into equivalent Python:

```Python
class FlowRefSymbol:
    def __init__(self, location, name, addr_space):
        self.addr_space = addr_space
        super().__init__(location, name)

    @property
    def pattern_expression(self):
        return None  # Cannot be used in pattern expressions

    @property
    def symbol_type(self):
        return 'start_symbol'

    def get_fixed_handle(self, hand, walker):
        ref_addr = walker.get_flow_ref_addr()
        hand.space = self.addr_space
        hand.offset_space = None
        hand.offset_offset = ref_addr.get_offset()
        hand.size = ref_addr.get_addr_size()

    @property
    def varnode(self):
        spc = ConstTpl(self.addr_space)
        off = ConstTpl(ConstTpl.const_type.j_flowref)
        sz_zero = ConstTpl()
        return VarnodeTpl(self.location, spc, off, sz_zero)

    def print(self, s, pos):
        val = pos.get_flow_ref_addr().get_offset()
        s.append('0x')
        s.print(hex(val))
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the specific classes and interfaces used in this code. The translation is based on equivalent concepts and data structures available in Python.