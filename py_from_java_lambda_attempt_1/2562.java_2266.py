Here is the translation of the Java code into Python:

```Python
class TraceStaticMappingManager:
    def __init__(self):
        self.mappings = []

    def add(self, range: 'AddressRange', lifespan: Range[int], program_url: str, address: str) -> 'TraceStaticMapping':
        for mapping in self.mappings:
            if (mapping.range.overlaps(range) and
                    mapping.lifespan.equals(lifespan) and
                    mapping.program_url == program_url and
                    mapping.address == address):
                return mapping

        new_mapping = TraceStaticMapping(range, lifespan, program_url, address)
        self.mappings.append(new_mapping)

        for i in range(len(self.mappings)):
            if (self.mappings[i].range.overlaps(range) and
                    self.mappings[i].lifespan.equals(lifespan) and
                    self.mappings[i].program_url == program_url and
                    self.mappings[i].address == address):
                return self.mappings.pop(i)
        return new_mapping

    def get_all_entries(self) -> list:
        return self.mappings[:]

    def find_containing(self, address: int, snap: int) -> 'TraceStaticMapping':
        for mapping in self.mappings:
            if (mapping.range.contains(address) and
                    mapping.snap == snap):
                return mapping

        return None


class TraceStaticMapping:
    def __init__(self, range: 'AddressRange', lifespan: Range[int], program_url: str, address: str):
        self.range = range
        self.lifespan = lifespan
        self.program_url = program_url
        self.address = address
        self.snap = None


class AddressRange:
    def __init__(self, from_address: int, to_address: int):
        self.from_address = from_address
        self.to_address = to_address

    def contains(self, address: int) -> bool:
        return self.from_address <= address <= self.to_address


class Range(int):
    def equals(self, other: 'Range[int]') -> bool:
        if not isinstance(other, Range):
            raise TypeError("Only a Range can be compared")

        return self == other

    def overlaps(self, other: 'Range[int]') -> bool:
        return (self.start <= other.stop and
                other.start <= self.stop)
```

This Python code defines the same classes as in Java. The `AddressRange` class represents an address range with a start and end address. The `Range` class is used to represent time ranges, which can be compared for equality or overlap.