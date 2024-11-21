class ARMEmulateInstructionStateModifier:
    def __init__(self, emu):
        self.TModeReg = None
        self.TBreg = None
        self.tMode = None
        self.aMode = None
        
        if emu is not None:
            super().__init__(emu)
            
            # Initialize TModeReg and TBreg based on the language
            try:
                from ghidra.program.model.lang import Register, RegisterValue
                
                self.TModeReg = Register("TMode")
                self.TBreg = Register("ISAModeSwitch")  # generic register which mirrors TB register value
                
                if self.TModeReg is not None and self.TBreg is None:
                    raise Exception(f"Expected language {emu.getLanguage().getLanguageID()} to have ISAModeSwitch register defined")
                
                self.tMode = RegisterValue(self.TModeReg, 1)
                self.aMode = RegisterValue(self.TModeReg, 0)
            except Exception as e:
                print(e)

    def registerPcodeOpBehavior(self, op_name):
        if op_name == "count_leading_zeroes":
            from ghidra.pcode.emulate import CountLeadingZerosOpBehavior
            self.registerPcodeOpBehavior(CountLeadingZerosOpBehavior())

    # Initialize TB register based upon context-register state before first instruction is executed.
    def initialExecuteCallback(self, emulate, current_address, context_register_value):
        if self.TModeReg is None:
            return  # Thumb mode not supported
        
        t_mode_value = BigInteger.ZERO
        if context_register_value is not None and isinstance(context_register_value.getRegisterValue(self.TModeReg), int):
            t_mode_value = BigInteger(int(context_register_value.getRegisterValue(self.TModeReg)))
        
        if t_mode_value != BigInteger.ZERO:
            t_mode_value = BigInteger.ONE
        
        emulate.getMemoryState().setValue(self.TBreg, t_mode_value)

    # Handle odd addresses which may occur when jumping/returning indirectly
    def postExecuteCallback(self, emulate, last_execute_address, last_execute_pcode, last_pcode_index, current_address):
        if self.TModeReg is None:
            return  # Thumb mode not supported
        
        if last_pcode_index < 0:
            return  # ignore fall-though condition
        
        op = last_execute_pcode[last_pcode_index].getOpcode()
        
        if (op != PcodeOp.BRANCH and
                op != PcodeOp.CBRANCH and
                op != PcodeOp.BRANCHIND and
                op != PcodeOp.CALL and
                op != PcodeOp.CALLIND and
                op != PcodeOp.RETURN):
            return  # only concerned with Branch, Call or Return ops
        
        tb_value = emulate.getMemoryState().getValue(self.TBreg)
        
        if tb_value == 1:
            # Thumb mode
            emulate.setContextRegisterValue(self.tMode)  # change context to be consistent with TB value
            
            if current_address.getOffset() % 2 != 0:
                emulate.setExecuteAddress(current_address.previous())
        elif tb_value == 0:
            if current_address.getOffset() % 2 != 1:
                raise LowlevelError("Flow to odd address occurred without setting TB register (Thumb mode)")
            
            # ARM mode
            emulate.setContextRegisterValue(self.aMode)  # change context to be consistent with TB value

class BigInteger(int):
    def __eq__(self, other):
        return int(self) == int(other)

PcodeOp = object()
LowlevelError = Exception
