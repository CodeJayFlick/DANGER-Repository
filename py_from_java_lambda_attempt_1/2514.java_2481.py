Here is a translation of the Java interface into equivalent Python classes:

```Python
class TraceGuestLanguage:
    def __init__(self):
        pass  # No direct equivalent in Python for constructor-like methods.

    def get_language(self) -> 'language':
        raise NotImplementedError("Method not implemented")

    def add_mapped_range(
            self, host_start: int, guest_start: int, length: int
    ) -> None:
        raise NotImplementedError("Method not implemented")

    def get_host_address_set(self) -> set[int]:
        raise NotImplementedError("Method not implemented")

    def get_guest_address_set(self) -> set[int]:
        raise NotImplementedError("Method not implemented")

    def map_host_to_guest(self, host_address: int) -> int:
        raise NotImplementedError("Method not implemented")

    def map_guest_to_host(self, guest_address: int) -> int:
        raise NotImplementedError("Method not implemented")

    def get_mapped_mem_buffer(
            self, snap: int, guest_address: int
    ) -> 'mem buffer':
        raise NotImplementedError("Method not implemented")

    def map_guest_instruction_addresses_to_host(self, set: list['instruction']) -> list['instruction']:
        raise NotImplementedError("Method not implemented")

    def delete(self) -> None:
        raise NotImplementedError("Method not implemented")
```

Note that the `get_language`, `add_mapped_range`, `get_host_address_set`, `get_guest_address_set`, `map_host_to_guest`, `map_guest_to_host`, `get_mapped_mem_buffer` and `delete` methods are abstract, meaning they have no implementation.