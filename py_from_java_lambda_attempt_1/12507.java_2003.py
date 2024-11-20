Here is the translation of the Java code into Python:

```Python
class RegisterManager:
    def __init__(self, registers: list, register_name_map: dict):
        self.registers = tuple(registers)
        self.register_name_map = frozenset(register_name_map.items())
        self.initialize()

    def initialize(self):
        register_names = sorted([reg.name for reg in self.registers])
        context_registers = [reg for reg in self.registers if reg.is_processor_context()]
        context_base_register = next((reg for reg in context_registers if reg.is_base_register()), None)

        size_map = {}
        address_map = {}

        for reg in self.registers:
            addr = reg.address
            list_ = address_map.get(addr, [])
            list_.append(reg)
            address_map[addr] = tuple(list_)
            if reg.is_processor_context():
                continue

            if reg.is_big_endian():
                populate_size_map_big_endian(reg)
            else:
                populate_size_map_little_endian(reg)

        if context_base_register is None:
            context_base_register = Register.NO_CONTEXT
        register_names.sort()
        self.register_names = tuple(register_names)
        size_map = {k: v for k, v in [(RegisterSizeKey(addr, 0), reg) for addr, reg in zip([reg.address for reg in self.registers], self.registers)]}
        context_registers = tuple(context_registers)

    def get_context_base_register(self):
        return self.context_base_register

    def get_context_registers(self):
        return self.context_registers

    def get_register_names(self):
        return self.register_names

    def get_register(self, addr: Address) -> Register:
        space = addr.get_address_space()
        if space.is_register_space() or space.has_mapped_registers():
            return size_map.get(RegisterSizeKey(addr, 0))
        return None

    def get_registers(self, addr: Address):
        space = addr.get_address_space()
        if space.is_register_space() or space.has_mapped_registers():
            list_ = address_map.get(get_global_address(addr), [])
            if list_:
                return tuple(list_)
        return ()

    @staticmethod
    def compare_vector_registers(reg1: Register, reg2: Register):
        if not (reg1.is_vector_register() and reg2.is_vector_register()):
            raise ValueError("compareVectorRegisters can only be applied to vector registers!")
        size_comp = int(reg2.get_bit_length()) - int(reg1.get_bit_length())
        if size_comp:
            return size_comp
        return int(reg1.get_offset()) - int(reg2.get_offset())

    def get_sorted_vector_registers(self):
        if self.sorted_vector_registers is None:
            list_ = [reg for reg in self.registers if reg.is_vector_register()]
            list_.sort(key=lambda x: (x.get_bit_length(), x.get_offset()))
            self.sorted_vector_registers = tuple(list_)
        return self.sorted_vector_registers

    def get_global_address(self, addr):
        if isinstance(addr, OldGenericNamespaceAddress):
            return addr.get_global_address()
        return addr


class RegisterSizeKey:
    def __init__(self, address: Address, size: int):
        self.address = address
        self.size = size < 0 and 0 or size

    def equals(self, obj) -> bool:
        if not isinstance(obj, type(self)):
            return False
        other = RegisterSizeKey(*obj)
        return self.address == other.address and self.size == other.size

    def hashCode(self):
        return hash((self.address, self.size))

    def __str__(self):
        return f"{{ {self.address}, size={self.size} }}"


class OldGenericNamespaceAddress:
    pass
```

Please note that Python does not have direct equivalent of Java's `List`, `Map` and other collections. Instead it uses built-in data structures like lists, dictionaries etc. Also the way you handle exceptions in python is different from java.