Here is the translation of the given Java code into Python:

```Python
class RegisterTranslator:
    def __init__(self, old_lang, new_lang):
        self.old_lang = old_lang
        self.new_lang = new_lang
        self.old_register_map = build_offset_map(old_lang.get_registers())
        self.new_register_map = build_offset_map(new_lang.get_registers())

    @staticmethod
    def compare_registers(r1, r2):
        return - (r2.bit_length() - r1.bit_length())

    @classmethod
    def build_offset_map(cls, registers):
        offset_map = {}
        for register in registers:
            addr = register.address
            if not addr.is_register_address or \
               not register.address_space.name.lower().startswith("register"):
                continue

            offset = int(addr.offset)
            register_list = offset_map.get(offset)

            if register_list is None:
                register_list = []
                offset_map[offset] = register_list

            register_list.append(register)

        for key in offset_map.keys():
            offset_map[key].sort(key=cls.compare_registers, reverse=True)

        return offset_map

    def get_old_register(self, offset, size):
        if offset not in self.old_register_map:
            return None
        list_ = self.old_register_map[offset]
        if size == 0:
            return list_[0]

        for i in range(len(list_) - 1, -1, -1):
            reg = list_[i]
            if reg.minimum_byte_size >= size:
                return reg

    def get_new_register(self, offset, size):
        if offset not in self.new_register_map:
            return None
        list_ = self.new_register_map[offset]
        if size == 0:
            return list_[0]

        for i in range(len(list_) - 1, -1, -1):
            reg = list_[i]
            if reg.minimum_byte_size >= size:
                return reg

    def get_new_register(self, old_reg):
        return self.new_lang.get_register(old_reg.name)

    def get_old_register(self, new_reg):
        return self.old_lang.get_register(new_reg.name)

    def get_new_registers(self):
        return self.new_lang.get_registers()
```

Note: This Python code assumes that the `Register`, `Language`, and other classes are defined elsewhere in your program.