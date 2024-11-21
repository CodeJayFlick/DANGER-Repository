class EmptyDebuggerObjectModel:
    def __init__(self):
        self.ram = AddressSpace("ram", 64, "RAM")
        self.factory = DefaultAddressFactory([self.ram])

    def get_address_factory(self):
        return self.factory

    def addr(self, off: int) -> 'Address':
        return self.ram.get_address(off)

    def range(self, min: int, max: int) -> 'AddressRange':
        return AddressRangeImpl(self.addr(min), self.addr(max))

    def add_model_root(self, root):
        super().add_model_root(root)
