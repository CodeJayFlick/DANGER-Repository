Here is the translation of the Java code into Python:

```Python
class DwarfCallFrameOpcodeParser:
    WHOLE_BYTE_MASK = 0xff
    HIGH_2_BITS_MASK = 0xc0
    LOW_6_BITS_MASK = 0x3f

    DW_CFA_NOP = 0x0
    DW_CFA_ADVANCE_LOC = 0x40
    DW_CFA_OFFSET = 0x80
    DW_CFA_RESTORE = 0xc0

    DW_CFA_SET_LOC = 1
    DW_CFA_ADVANCE_LOC1 = 2
    DW_CFA_ADVANCE_LOC2 = 3
    DW_CFA_ADVANCE_LOC4 = 4
    DW_CFA_OFFSET_EXTENDED = 5
    DW_CFA_RESTORE_EXTENDED = 6
    DW_CFA_UNDEFINED = 7
    DW_CFA_SAME_VALUE = 8
    DW_CFA_REGISTER = 9
    DW_CFA_REMEMBER_STATE = 0xa
    DW_CFA_RESTORE_STATE = 0xb

    DW_CFA_DEF_CFA = 0xc
    DW_CFA_DEF_CFA_REGISTER = 0xd
    DW_CFA_DEF_CFA_OFFSET = 0xe
    DW_CFA_DEF_CFA_EXPRESSION = 0xf

    DW_CFA_EXPRESSION = 10
    DW_CFA_OFFSET_EXTENDED_SF = 11
    DW_CFA_DEF_CFA_SF = 12
    DW_CFA_DEF_CFA_OFFSET_SF = 13
    DW_CFA_VAL_OFFSET = 14
    DW_CFA_VAL_OFFSET_SF = 15

    DW_CFA_MIPS_ADVANCE_LOC8 = 0x1d
    DW_CFA_GNU_WINDOW_SAVE = 0x2d
    DW_CFA_GNU_ARGS_SIZE = 0x2e
    DW_CFA_LO_USER = 0x1c
    DW_CFA_HI_USER = 0x3f

    def __init__(self, program, address, length):
        self.program = program
        self.address = address
        self.length = length

    def parse(self):
        current_address = self.address
        limit = self.address.add(self.length)

        while current_address < limit:
            opcode_or_param = GccAnalysisUtils.read_byte(self.program, current_address) & DwarfCallFrameOpcodeParser.WHOLE_BYTE_MASK
            primary_opcode = (opcode_or_param & DwarfCallFrameOpcodeParser.HIGH_2_BITS_MASK) != 0

            if primary_opcode:
                switch(opcode):
                    case DW_CFA_ADVANCE_LOC:
                        sb.append("DW_CFA_advance_loc delta[" + str(ex_opcode_or_param) + "]")
                        break
                    # ... rest of the cases ...
            else:
                switch(ex_opcode_or_param):
                    case DW_CFA_NOP:
                        sb.append("DW_CFA_nop")
                        break
                    # ... rest of the cases ...

            SetCommentCmd.create_comment(self.program, instr_addr, sb.toString(), CodeUnit.EOL_COMMENT)

            Msg.info(self, sb.toString())

    def get_uleb128_length(program, current_address):
        length = 0
        byte_val = GccAnalysisUtils.read_byte(program, current_address)
        while (byte_val & 0x80) != 0:
            length += 1
            byte_val &= ~0x80
        return length + 1

    def get_qword_length(program, current_address):
        length = 8
        return length