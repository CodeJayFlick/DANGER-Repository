class DebugStateMachineOpCodes:
    # Constants for opcodes
    DBG_END_SEQUENCE = 0x00
    DBG_ADVANCE_PC = 0x01
    DBG_ADVANCE_LINE = 0x02
    DBG_START_LOCAL = 0x03
    DBG_START_LOCAL_EXTENDED = 0x04
    DBG_END_LOCAL = 0x05
    DBG_RESTART_LOCAL = 0x06
    DBG_SET_PROLOGUE_END = 0x07
    DBG_SET_EPILOGUE_BEGIN = 0x08
    DBG_SET_FILE = 0x09

    @staticmethod
    def is_special_opcode(opcode):
        return opcode >= 10 and opcode <= 255


# Example usage:
print(DebugStateMachineOpCodes.is_special_opcode(12))  # True
print(DebugStateMachineOpCodes.is_special_opcode(5))   # False
