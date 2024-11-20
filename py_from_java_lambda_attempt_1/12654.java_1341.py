Here is the translation of the Java code into Python:

```Python
class PcodeOp:
    def __init__(self, seqnum, op, numinputs=0, out=None):
        self.opcode = op
        self.seqnum = seqnum
        if numinputs > 0:
            self.input = [None] * numinputs
        else:
            self.input = []
        self.output = out

    def get_opcode(self):
        return self.opcode

    def get_num_inputs(self):
        if not self.input:
            return 0
        return len(self.input)

    def get_inputs(self):
        return self.input[:]

    def get_input(self, i):
        if i >= len(self.input) or i < 0:
            return None
        return self.input[i]

    def set_opcode(self, op):
        self.opcode = op

    def set_output(self, out):
        self.output = out

    @staticmethod
    def get_mnemonic(op):
        mnemonics = {
            PcodeOp.UNIMPLEMENTED: "UNIMPLEMENTED",
            PcodeOp.COPY: "COPY",
            # ... and so on for all the opcodes
        }
        return mnemonics.get(op, "INVALID_OP")

class SequenceNumber:
    def __init__(self):
        self.time = None
        self.order = None

    @staticmethod
    def read_xml(parser):
        el = parser.start("seqnum")
        time = int(el.getAttribute("time"))
        order = int(el.getAttribute("order"))
        return PcodeOp.SequenceNumber(time, order)

class Varnode:
    pass  # This class is not implemented in the Java code

# Define all the opcodes
PcodeOp.UNIMPLEMENTED = 0
PcodeOp.COPY = 1
PcodeOp.LOAD = 2
PcodeOp.STORE = 3
# ... and so on for all the opcodes

def generate_opcode_table():
    PcodeOp.mnemonics = {}
    for i in range(PcodeOp.PCODE_MAX):
        PcodeOp.mnemonics[PcodeOp.get_mnemonic(i)] = i
    # Add more mnemonics as needed

# Define a function to get the opcode from a mnemonic string
def get_opcode(s):
    if not PcodeOp.mnemonics:
        generate_opcode_table()
    return PcodeOp.mnemonics.get(s, None)

PcodeOp.PCODE_MAX = 73
```

Please note that this is just one possible translation of the Java code into Python. The actual implementation may vary depending on your specific requirements and constraints.