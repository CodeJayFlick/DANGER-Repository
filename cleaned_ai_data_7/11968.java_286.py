class AddressMap:
    INVALID_ADDRESS_KEY = -1

    def __init__(self):
        pass

    def get_key(self, addr: 'Address', create: bool) -> int:
        # implement the method here
        pass

    def get_absolute_encoding(self, addr: 'Address', create: bool) -> int:
        # implement the method here
        pass

    def find_key_range(self, key_ranges: list['KeyRange'], addr: 'Address') -> int:
        # implement the method here
        pass

    def get_key_ranges(self, start: 'Address', end: 'Address', create: bool) -> list['KeyRange']:
        # implement the method here
        pass

    def get_key_ranges(self, set_view: 'AddressSetView', create: bool) -> list['KeyRange']:
        # implement the method here
        pass

    def decode_address(self, value: int) -> 'Address':
        # implement the method here
        pass

    def get_address_factory(self) -> 'AddressFactory':
        # implement the method here
        pass

    def set_language(self, new_language: str, addr_factory: 'AddressFactory', translator: 'LanguageTranslator') -> None:
        # implement the method here
        pass

    def invalidate_cache(self) -> None:
        # implement the method here
        pass

    def rename_overlay_space(self, old_name: str, new_name: str) -> None:
        # implement the method here
        pass

    def delete_overlay_space(self, name: str) -> None:
        # implement the method here
        pass

    def has_same_key_base(self, addr_key1: int, addr_key2: int) -> bool:
        # implement the method here
        pass

    def is_key_range_min(self, addr_key: int) -> bool:
        # implement the method here
        pass

    def is_key_range_max(self, addr_key: int) -> bool:
        # implement the method here
        pass

class KeyRange:
    pass

class AddressSetView:
    pass

class LanguageTranslator:
    pass

class AddressFactory:
    pass
