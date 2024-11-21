class AddressChangeSet:
    def __init__(self):
        self.address_set = set()

    def get_address_set(self) -> 'set[Address]':
        return self.address_set

    def add(self, addr_set: 'set[Address]'):
        self.address_set.update(addr_set)

    def add_range(self, start_addr: Address, end_addr: Address):
        for addr in range(start_addr, end_addr + 1):
            self.add({addr})
