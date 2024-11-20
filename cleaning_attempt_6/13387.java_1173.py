class TRICOREEmulateInstructionStateModifier:
    def __init__(self, emu):
        self.FCX = None
        self.PCXI = None
        self.LCX = None
        self PSW = None
        self.a10 = None
        self.d8 = None
        self.a12 = None
        self.d12 = None

        super().__init__(emu)

        self.register_pcode_op_behavior("saveCallerState", tricore_SaveCallerState())
        self.register_pcode_op_behavior("restoreCallerState", tricore_RestoreCallerState())

    class tricore_SaveCallerState:
        def evaluate(self, emu, output_varnode, inputs):
            num_args = len(inputs) - 1
            if num_args != 3:
                raise LowlevelError(f"{self.__class__.__name__}: requires 3 inputs (FCX, LCX, PCXI), got {num_args}")

            memory_state = emu.get_memory_state()

            FCX_value = memory_state[FCX]
            new_FCX_value = None

            if FCX_value == BigInteger.ZERO:
                new_FCX_value = FCX_value.add(BigInteger.ONE)
            else:
                new_FCX_value = FCX_value

            EA_addr = emu.get_execute_address().get_new_address(new_FCX_value.long_value())
            address_space = emu.get_execute_address().get_address_space()

            out_bytes = bytearray(4 * 16)

            index = 0
            index += copy_register_to_array(PCXI, PCXI.bit_length() // 8, memory_state, out_bytes, index)
            index += copy_register_to_array(PSW, PSW.bit_length() // 8, memory_state, out_bytes, index)
            index += copy_register_to_array(a10, a10.bit_length() * 2 // 8, memory_state, out_bytes, index)
            index += copy_register_to_array(d8, d8.bit_length() * 4 // 8, memory_state, out_bytes, index)
            index += copy_register_to_array(a12, a12.bit_length() * 4 // 8, memory_state, out_bytes, index)
            index += copy_register_to_array(d12, d12.bit_length() * 4 // 8, memory_state, out_bytes, index)

            memory_state.set_chunk(out_bytes, address_space, EA_addr.offset(), len(out_bytes))

    class tricore_RestoreCallerState:
        def evaluate(self, emu, output_varnode, inputs):
            num_args = len(inputs) - 1
            if num_args != 3:
                raise LowlevelError(f"{self.__class__.__name__}: requires 3 inputs (FCX, LCX, PCXI), got {num_args}")

            memory_state = emu.get_memory_state()

            FCX_value = memory_state[FCX]
            PCXI_value = memory_state[PCXI]

            EA_addr = emu.get_execute_address().get_new_address(PCXI_value.long_value())
            address_space = emu.get_execute_address().get_address_space()

            in_bytes = bytearray(4 * 16)
            memory_state.get_chunk(in_bytes, address_space, EA_addr.offset(), len(in_bytes), True)

    def copy_register_to_array(self, reg, length, memory_state, out_bytes, index):
        v_bytes = bytearray(length)
        nread = memory_state.get_chunk(v_bytes, reg.address_space, reg.offset(), length, False)
        System.arraycopy(v_bytes, 0, out_bytes, index, len(out_bytes))
        return nread

    def cache_registers(self, emu):
        self.FCX = emu.language().get_register("FCX")
        self.LCX = emu.language().get_register("LCX")
        self.PCXI = emu.language().get_register("PCXI")
        self PSW = emu.language().get_register("PSW")
        self.a10 = emu.language().get_register("a10")
        self.d8 = emu.language().get_register("d8")
        self.a12 = emu.language().get_register("a12")
        self.d12 = emu.language().get_register("d12")

    def register_pcode_op_behavior(self, name, behavior):
        pass

class LowlevelError(Exception):
    pass
