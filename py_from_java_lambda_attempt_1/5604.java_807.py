Here is the translation of the given Java code into Python:

```Python
class AddressBasedIndexMapper:
    def __init__(self, from_map, to_map):
        self.from_map = from_map
        self.to_map = to_map

    def map(self, value: int) -> int:
        address = self.from_map.get_address(value)
        if address is None:
            return 0
        mapped_value = self.to_map.get_index(address)
        return mapped_value or 0


class AddressIndexMap:
    pass


from typing import BigInteger

# Usage example:

if __name__ == "__main__":
    from_map = AddressIndexMap()
    to_map = AddressIndexMap()

    mapper = AddressBasedIndexMapper(from_map, to_map)

    value = 123
    mapped_value = mapper.map(value)
    print(mapped_value)