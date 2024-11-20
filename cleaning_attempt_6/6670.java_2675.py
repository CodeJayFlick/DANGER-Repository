class ContextRegisterFilter:
    def __init__(self):
        self.context_registers = set()
        self.values = {}

    def add_reg_and_value_to_filter(self, context_register: str, value: int) -> None:
        if context_register in self.context_registers:
            raise ValueError("Filter can have only one value per register!")
        self.context_registers.add(context_register)
        self.values[context_register] = value

    def allows(self, context_register_infos: list) -> bool:
        for c_info in context_register_infos:
            if c_info.get_context_register() in self.context_registers and not self.values[c_info.get_context_register()].equals(c_info.get_value()):
                return False
        return True

    def __str__(self):
        sb = StringBuilder()
        sb.append("Context Register Filter:\n")
        for c_reg in self.context_registers:
            sb.append(f"{c_reg}: {self.values[c_reg]}\n")
        sb.append("\n")
        return str(sb)

    def get_compact_string(self) -> str:
        registers = list(self.context_registers)
        sb = StringBuilder()
        for i, reg in enumerate(registers):
            sb.append(f"{reg}={self.values[reg]}")
            if i < len(registers) - 1:
                sb.append("; ")
        return str(sb)

    def __hash__(self):
        hash_value = 17
        hash_value = 31 * hash_value + hash(self.context_registers)
        hash_value = 31 * hash_value + hash(self.values)
        return hash_value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ContextRegisterFilter):
            return False
        if self.context_registers != other.context_registers or self.values != other.values:
            return False
        return True

    @property
    def value_map(self) -> dict:
        return self.values
