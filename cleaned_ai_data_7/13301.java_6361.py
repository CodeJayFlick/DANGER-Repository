class MIPSEmulateInstructionStateModifier:
    def __init__(self, emu):
        self.emu = emu
        self.ism_reg = None
        self.isa_mode_reg = None
        self.ISA_MODE0 = None
        self.ISA_MODE1 = None

        if not (ism_reg := get_register("ISAModeSwitch")) or not (isa_mode_reg := get_register("ISA_MODE")):
            raise RuntimeError(f"Expected language {language.get_language_id()} to have ISM and ISA_MODE registers defined")

        self.ISA_MODE0 = RegisterValue(isa_mode_reg, 0)
        self.ISA_MODE1 = RegisterValue(isa_mode_reg, 1)

    def register_pcode_op_behavior(self, op_name):
        if op_name == "countLeadingZeros":
            return CountLeadingZerosOpBehavior()
        elif op_name == "countLeadingOnes":
            return CountLeadingOnesOpBehavior()

    def initial_execute_callback(self, emulate, current_address, context_register_value):
        isa_mode_value = 0
        if context_register_value:
            isa_mode_value = context_register_value.get_unsigned_value_ignore_mask()

        if not (isa_mode_value == 0):
            isa_mode_value = 1

        self.emu.memory_state.set_value(self.ism_reg, isa_mode_value)

    def post_execute_callback(self, emulate, last_execute_address, last_pcode_op_array, last_pcode_index, current_address):
        if last_pcode_index < 0:
            return

        last_opcode = last_pcode_op_array[last_pcode_index].get_opcode()

        if not (last_opcode in [PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND, PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.RETURN]):
            return

        tb_value = self.emu.memory_state.get_value(self.ism_reg)

        if tb_value == 1:
            # Thumb mode
            self.emu.set_context_register_value(self.ISA_MODE1)
            if current_address.offset & 0x1:
                emulate.set_execute_address(current_address.previous())
        else:
            # MIPS mode
            if current_address.offset & 0x1:
                raise LowlevelError("Flow to odd address occurred without setting ISM register (16-bit mode)")

            self.emu.set_context_register_value(self.ISA_MODE0)

class RegisterValue:
    def __init__(self, reg, value):
        self.reg = reg
        self.value = value

def get_register(name):
    # This function should return the requested register.
    pass

class CountLeadingZerosOpBehavior:
    # This class is not implemented in this translation.
    pass

class CountLeadingOnesOpBehavior:
    # This class is not implemented in this translation.
    pass
