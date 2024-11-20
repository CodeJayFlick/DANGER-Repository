Here is the translation of the given Java code into equivalent Python:

```Python
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

```

Note that Python does not have direct equivalents to Java's `@Entity`, `@NonNull`, `@PrimaryKey`, and other annotations. The equivalent functionality can be achieved using Python classes, properties, and type hints.

Also note that the given code is part of a larger program, so it may require additional context or modifications to work correctly in its original form.