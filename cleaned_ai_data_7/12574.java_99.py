class RegisterChangeSet:
    def __init__(self):
        self.change_set = set()

    def add_register_range(self, addr1: int, addr2: int) -> None:
        """Adds the ranges of addresses that have register changes."""
        for address in range(addr1, addr2 + 1):
            self.change_set.add(address)

    def get_register_address_set(self) -> set[int]:
        """Returns the set of Addresses containing register changes."""
        return self.change_set
