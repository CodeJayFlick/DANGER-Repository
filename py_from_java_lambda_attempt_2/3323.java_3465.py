Here is the translation of the Java code into Python:

```Python
class ExternalsAddressTranslator:
    def __init__(self, destination_program: 'Program', source_program: 'Program'):
        self.destination_program = destination_program
        self.source_program = source_program
        self.address_map = {}  # key = source, value = destination

    @property
    def destination_program(self):
        return self._destination_program

    @destination_program.setter
    def destination_program(self, program: 'Program'):
        self._destination_program = program

    @property
    def source_program(self):
        return self._source_program

    @source_program.setter
    def source_program(self, program: 'Program'):
        self._source_program = program

    def set_pair(self, destination_address: 'Address', source_address: 'Address'):
        if destination_address is not None:
            self.address_map[destination_address] = source_address
        else:
            del self.address_map[source_address]

    def get_destination_address(self, source_address):
        return self.address_map.get(source_address)

    @property
    def one_for_one_translator(self) -> bool:
        return True

    def get_address_set(self, source_address_set: 'AddressSetView') -> 'AddressSet':
        if source_address_set is None or not source_address_set.is_empty():
            raise AddressTranslationException("An external address translator can only handle a single address at a time.")
        destination_set = set()
        for source_address in source_address_set:
            destination_address = self.address_map.get(source_address)
            if destination_address is not None:
                destination_set.add(destination_address)
        return list(destination_set)

    def get_address_range(self, source_address_range: 'AddressRange') -> 'AddressRange':
        if source_address_range is None or source_address_range.length != 1:
            raise AddressTranslationException("An external address translator can only handle a single address at a time.")
        destination_address = self.address_map.get(source_address_range.min)
        return AddressRangeImpl(destination_address, destination_address)

class Program:
    pass

class Address:
    pass

class AddressSetView:
    def is_empty(self) -> bool:
        raise NotImplementedError()

    def get_min_address(self):
        raise NotImplementedError()

    def num_addresses(self) -> int:
        raise NotImplementedError()
```

Please note that this translation assumes the following:

- The `Program`, `Address`, and `AddressSet` classes are defined elsewhere in your code.
- The `AddressTranslationException` class is also defined elsewhere in your code.