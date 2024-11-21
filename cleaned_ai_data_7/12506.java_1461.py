class Register:
    def __init__(self, name: str, description: str, address: int, num_bytes: int, least_significant_bit: int, bit_length: int, big_endian: bool, type_flags: int):
        self.name = name
        self.description = description
        self.address = address
        self.num_bytes = num_bytes
        self.least_significant_bit = least_significant_bit
        self.bit_length = bit_length
        self.big_endian = big_endian
        self.type_flags = type_flags

    def add_alias(self, alias: str):
        self.aliases.append(alias)

class RegisterBuilder:
    def __init__(self):
        self.register_list = []
        self.register_map = {}
        self.context_address = None

    def add_register(self, name: str, description: str, address: int, num_bytes: int, least_significant_bit: int, bit_length: int, big_endian: bool, type_flags: int) -> Register:
        register = Register(name, description, address, num_bytes, least_significant_bit, bit_length, big_endian, type_flags)
        self.add_register(register)

    def add_register(self, register: Register):
        if self.register_map.get(register.name) is not None:
            print("Duplicate register name:", register.name)
            return
        for reg in self.register_list:
            if reg.address == register.address and reg.least_significant_bit == register.least_significant_bit and reg.bit_length == register.bit_length:
                reg.add_alias(register.name)
                self.register_map[register.name] = reg
                return
        if not hasattr(self, 'context_address') or not register.is_processor_context():
            self.context_address = register.address
        self.register_list.append(register)
        self.register_map[register.name] = register

    def add_register_to_name_map(self, name: str, register: Register):
        self.register_map[name] = register
        self.register_map[name.lower()] = register
        self.register_map[name.upper()] = register

    def remove_register_from_name_map(self, name: str):
        if name in self.register_map:
            del self.register_map[name]
            for key in [key for key in list(self.register_map.keys()) if key.startswith(name)]:
                del self.register_map[key]

    @property
    def process_context_address(self) -> int:
        return self.context_address

    def compute_registers(self):
        reg_list = []
        unprocessed = self.register_list.copy()
        bit_size = 1
        while len(unprocessed) > 0:
            next_larger_size = float('inf')
            for register in unprocessed:
                if register.bit_length == bit_size:
                    children = get_children(register, reg_list)
                    register.set_child_registers(children)
                    reg_list.append(register)
                    unprocessed.remove(register)
                else:
                    next_larger_size = min(next_larger_size, register.bit_length)
            bit_size = next_larger_size
        return self.register_list

    def get_children(self, parent: Register, reg_list):
        children = []
        for register in reg_list.copy():
            if contains(parent, register):
                children.append(register)
                reg_list.remove(register)
        return children

    @staticmethod
    def contains(parent: Register, child: Register) -> bool:
        if not parent.address_space == child.address_space:
            return False
        if (child.offset < parent.offset or 
           child.offset + child.minimum_byte_size > parent.offset + parent.minimum_byte_size):
            return False
        if parent.least_significant_bit != 0:
            return False
        if parent.bit_length != parent.minimum_byte_size * 8:
            return False
        return True

    def get_register(self, name: str) -> Register | None:
        return self.register_map.get(name)

    @staticmethod
    def rename_register(old_name: str, new_name: str):
        register = self.register_map[old_name]
        if not hasattr(register, 'rename'):
            raise Exception("Register is unable to support the definition of lanes.")
        register.rename(new_name)
        del self.register_map[old_name]
        for key in [key for key in list(self.register_map.keys()) if key.startswith(old_name)]:
            del self.register_map[key]
        self.add_register_to_name_map(new_name, register)

    def add_alias(self, register_name: str, alias: str):
        register = self.get_register(register_name)
        if not hasattr(register, 'add_alias'):
            raise Exception("Register is unable to support the definition of lanes.")
        register.add_alias(alias)
        self.register_map[alias] = register

    @staticmethod
    def set_group(register_name: str, group_name: str):
        pass  # This method does nothing in Python.

    @staticmethod
    def set_flag(register_name: str, flag: int):
        pass  # This method does nothing in Python.

    @staticmethod
    def add_lane_size(register_name: str, lane_size_in_bytes: int):
        register = self.get_register(register_name)
        if not hasattr(register, 'add_lane_size'):
            raise Exception("Register is unable to support the definition of lanes.")
        register.add_lane_size(lane_size_in_bytes)

def get_children(parent: Register, reg_list) -> list:
    children = []
    for register in reg_list.copy():
        if contains(parent, register):
            children.append(register)
            reg_list.remove(register)
    return children

# Example usage
builder = RegisterBuilder()
register1 = builder.add_register("Register 1", "Description of Register 1", 0x10000000, 4, 0, 32, True, 0)
register2 = builder.add_register("Register 2", "Description of Register 2", 0x20000000, 8, 0, 64, False, 0)

print(builder.get_process_context_address())
