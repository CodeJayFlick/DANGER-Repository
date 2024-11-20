class AddressBookEntry:
    TABLE_NAME = "address_book"

    def __init__(self, address: str, label: str):
        self.address = address
        self.label = label

    @property
    def address(self) -> str:
        return self._address

    @address.setter
    def address(self, value: str):
        self._address = value

    @property
    def label(self) -> str:
        return self._label

    @label.setter
    def label(self, value: str):
        self._label = value


def as_map(entries: list[AddressBookEntry]) -> dict[str, AddressBookEntry]:
    if entries is None:
        return {}
    address_book = {}
    for entry in entries:
        address_book[entry.address] = entry
    return address_book

