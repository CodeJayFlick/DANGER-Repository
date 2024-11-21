Here is the translation of the given Java code into equivalent Python:

```Python
class ParserWalker:
    def __init__(self, const_context):
        self.const_context = const_context
        self.breadcrumb = [0] * 32

    @property
    def parser_context(self):
        return self.const_context

    def base_state(self):
        self.point = self.const_context.base_state
        self.depth = 0
        self.breadcrumb[0] = 0

    def set_out_of_band_state(self, ct, index, tempstate, otherwalker):
        pt = otherwalker.point
        curdepth = otherwalker.depth
        while pt.ct != ct:
            if curdepth <= 0:
                return
            curdepth -= 1
            pt = pt.parent

        sym = ct.get_operand(index)
        i = sym.get_offset_base()
        if i < 0:
            tempstate.offset = pt.offset + sym.get_relative_offset()
        else:
            tempstate.offset = pt.resolve[index].offset

        tempstate.ct = ct
        tempstate.length = pt.length
        self.point = tempstate
        self.depth = 0
        self.breadcrumb[0] = 0

    def is_state(self):
        return self.point is not None

    def push_operand(self, i):
        self.breadcrumb[self.depth:] = [i + 1]
        self.point = self.point.resolve[i]
        self.breadcrumb[self.depth] = 0
        self.depth += 1

    def pop_operand(self):
        if self.depth > 0:
            self.point = self.point.parent
            self.depth -= 1

    def get_offset(self, i):
        if i < 0:
            return self.point.offset
        op = self.point.resolve[i]
        return op.offset + op.length

    @property
    def constructor(self):
        return self.point.ct

    def get_operand(self):
        return self.breadcrumb[self.depth - 1]

    def get_parent_handle(self, i):
        if i < 0:
            return self.point.hand
        else:
            return self.point.resolve[i].hand

    @property
    def cur_space(self):
        return self.const_context.cur_space

    @property
    def const_space(self):
        return self.const_context.const_space

    @property
    def addr(self):
        return self.const_context.addr

    @property
    def naddr(self):
        return self.const_context.naddr

    @property
    def flow_ref_addr(self):
        return self.const_context.flow_ref_addr

    @property
    def flow_dest_addr(self):
        return self.const_context.flow_dest_addr

    @property
    def length(self):
        return self.const_context.length

    def get_instruction_bytes(self, byteoff, numbytes):
        if hasattr(self.const_context, 'get_instruction_bytes'):
            return getattr(self.const_context, 'get_instruction_bytes')(byteoff, numbytes)
        else:
            raise AttributeError("const_context has no attribute 'get_instruction_bytes'")

    def get_context_bytes(self, byteoff, numbytes):
        if hasattr(self.const_context, 'get_context_bytes'):
            return getattr(self.const_context, 'get_context_bytes')(byteoff, numbytes)
        else:
            raise AttributeError("const_context has no attribute 'get_context_bytes'")

    def get_instruction_bits(self, startbit, size):
        if hasattr(self.const_context, 'get_instruction_bits'):
            return getattr(self.const_context, 'get_instruction_bits')(startbit, size)
        else:
            raise AttributeError("const_context has no attribute 'get_instruction_bits'")

    def get_context_bits(self, startbit, size):
        if hasattr(self.const_context, 'get_context_bits'):
            return getattr(self.const_context, 'get_context_bits')(startbit, size)
        else:
            raise AttributeError("const_context has no attribute 'get_context_bits'")
```

This Python code is equivalent to the given Java code. It defines a class `ParserWalker` with various methods and properties that mimic their counterparts in the original Java code.