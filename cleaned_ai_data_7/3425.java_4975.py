class RegisterContextBuilder:
    def __init__(self, program: object, reg: object, is_bit_register: bool):
        self.program = program
        self.reg = reg
        self.is_bit_register = is_bit_register

    def set_value_unknown(self) -> None:
        self.value = None
        self.set_addr = None

    def set_value_at(self, instr: object, new_value: int | str, value_assumed: bool) -> None:
        if not (instr and new_value):
            raise ValueError("Instr and New Value required")
        self.set_addr = value_assumed and instr.get_min_address() or instr.get_fall_through()
        if self.set_addr is not None:
            self.value = new_value
            if self.mask is not None:
                self.value &= self.mask

    def set_value_at(self, instr: object, new_value: int | str) -> None:
        self.set_value_at(instr, new_value, False)

    def has_value(self) -> bool:
        return self.value is not None

    def value(self) -> int | str:
        if self.value is None:
            raise ValueError("Value unknown")
        return self.value

    def long_value(self) -> int:
        if self.value is None:
            raise ValueError("Value unknown")
        return int(self.value)

    def write_value(self, range_end: object) -> bool:
        if self.set_addr and self.set_addr < range_end:
            try:
                self.program.get_program_context().set_value(
                    self.reg,
                    self.set_addr,
                    range_end,
                    self.value
                )
            except ContextChangeException as e:
                pass  # reg is never processor context register
            return True
        return False

    def set_bit_at(self, instr: object, bit: int | str, right_shift_factor: int) -> bool:
        if not (bit and isinstance(bit, int)):
            self.value = None
            return False
        bit_num = bit - right_shift_factor
        return self.set_bit_at(instr, bit_num)

    def set_bit_at(self, instr: object, bit: int | str) -> bool:
        if self.is_bit_register or not (self.value is None):
            self.set_addr = instr.get_fall_through()
            if self.set_addr and isinstance(self.value, int):
                return True
            else:
                self.value = 0

    def clear_bit_at(self, instr: object, bit: int | str, right_shift_factor: int) -> bool:
        if not (bit and isinstance(bit, int)):
            self.value = None
            return False
        bit_num = bit - right_shift_factor
        return self.clear_bit_at(instr, bit_num)

    def clear_bit_at(self, instr: object, bit: int | str) -> bool:
        if self.is_bit_register or not (self.value is None):
            self.set_addr = instr.get_fall_through()
            if self.set_addr and isinstance(self.value, int):
                return True
            else:
                self.value = 0

    def set_value_at_address(self, value_from: object) -> bool | str:
        if self.value or not (value_from is None):
            raise ValueError("Value unknown")
        val = self.program.get_program_context().get_value(
            self.reg,
            value_from,
            False
        )
        if val and isinstance(val, int):
            return True
        else:
            self.set_value_unknown()
