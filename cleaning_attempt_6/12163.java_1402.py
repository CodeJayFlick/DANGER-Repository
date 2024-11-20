class GenericAddressSpace:
    def __init__(self, name: str, size: int, unit_size: int = 1, type: int = None, unique_id: int = None):
        pass

    def get_address(self, offset: int) -> 'GenericAddress':
        return GenericAddress(self, offset)

    def get_address_in_this_space_only(self, offset: int) -> 'GenericAddress':
        return self.get_address(offset)

    @property
    def show_space_name(self) -> bool:
        pass

    def set_show_space_name(self, value: bool):
        pass


class GenericAddress:
    def __init__(self, address_space: 'GenericAddressSpace', offset: int):
        self.address_space = address_space
        self.offset = offset
