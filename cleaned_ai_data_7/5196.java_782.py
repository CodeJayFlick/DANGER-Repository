class RelocLgSetOrBySection:
    def __init__(self, reader):
        value = reader.read_next_short() & 0xffff
        self.opcode = (value & 0xfc00) >> 10
        self.subopcode = (value & 0x0330) >> 6
        self.index = ((value & 0x003f) << 16) | reader.read_next_short() & 0xffff

    def is_match(self):
        return self.opcode == 0x2d

    def get_size_in_bytes(self):
        return 4

    @property
    def subopcode(self):
        return self.subopcode

    @property
    def index(self):
        return self.index

    def apply(self, import_state, reloc_state, header, program, log, monitor):
        raise RuntimeError("Unhandled relocation: RelocLgSetOrBySection")
