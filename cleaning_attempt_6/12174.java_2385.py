class SpecialAddress:
    def __init__(self, name):
        super().__init__(GenericAddressSpace(name, 0, 1, "NONE", -1), 0)

    def __str__(self):
        return self.addr_space.name

    def __repr__(self):
        return str(self)

    def to_string(self, show_address_space=False):
        if show_address_space:
            return self.addr_space.name
        else:
            return ""

class GenericAddressSpace:
    def __init__(self, name, start, end, type_, size):
        self.name = name
        self.start = start
        self.end = end
        self.type_ = type_
        self.size = size

addr_spaces = [GenericAddressSpace("name1", 0, 100, "NONE", -1),
               GenericAddressSpace("name2", 101, 200, "NONE", -1)]

special_addresses = []
for addr_space in addr_spaces:
    special_address = SpecialAddress(addr_space.name)
    special_addresses.append(special_address)

print([str(sa) for sa in special_addresses])
