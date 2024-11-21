Here is the translation of the given Java code into Python:

```Python
class OpTemplate:
    def __init__(self, opc, in_, out_, af):
        self.opcode = opc
        self.input = in_
        self.output = out_
        self.num_inputs = len(in_)
        self.address_factory = af

    def get_pcode(self, handles, position, op_sequence_number, off) -> PcodeOp:
        opcode_ = self.opcode
        
        if self.output is not None:
            out_ = self.output.resolve(handles, position, off)
        else:
            out_ = None
        in_ = [input_.resolve(handles, position, off) for input_ in self.input]
        
        # optimization: convert STOREs and LOADs to COPYs if possible
        if opcode_ == PcodeOp.STORE:
            ptr = in_[1]
            if ptr.is_constant():
                space = in_[0]
                src = in_[2]
                addr = self.address_factory.get_address((int)(space.offset), (ptr.offset))
                out_ = Varnode(addr, src.size)
                in_ = [src]
                opcode_ = PcodeOp.COPY
        elif opcode_ == PcodeOp.LOAD:
            ptr = in_[1]
            if ptr.is_constant():
                space = in_[0]
                dest = out_
                addr = self.address_factory.get_address((int)(space.offset), (ptr.offset))
                in_ = [Varnode(addr, dest.size)]
                opcode_ = PcodeOp.COPY
        
        # just before emitting pcode, trim constant varnodes to proper size
        for i in range(len(in_)):
            in_[i].trim()
        
        return PcodeOp(position.start_addr(), op_sequence_number, opcode_, in_, out_)
    
    def get_opcode(self) -> int:
        return self.opcode
    
    def get_input(self, i: int) -> 'VarnodeTemplate':
        return self.input[i]
    
    def get_output(self) -> 'VarnodeTemplate':
        return self.output
    
    def set_omit(self, ref):
        self.omit = ref

    def omit(self) -> bool:
        if hasattr(self, 'omit'):
            return (self.omit is not None and not self.omit.dynamic())
        else:
            return False
```

Note: The `PcodeOp`, `VarnodeTemplate` classes are assumed to be defined elsewhere in the code.