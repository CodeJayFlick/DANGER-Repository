class RangeMapAdapter:
    def __init__(self):
        pass

    def get_value(self, address: 'Address') -> bytes | None:
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def move_address_range(
            self,
            from_addr: 'Address',
            to_addr: 'Address',
            length: int,
            monitor: 'TaskMonitor'
    ) -> None:
        """Move all values within an address range to a new range."""
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def set(self, start: 'Address', end: 'Address', bytes: bytes) -> None:
        """Associates the given byte array with all indexes in the given range. Any existing values will be overwritten."""
        pass

    def get_address_range_iterator(self, start: 'Address', end: 'Address') -> 'IndexRangeIterator':
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_address_range_iterator(self) -> 'IndexRangeIterator':
        """Returns an IndexRangeIterator over all stored values."""
        pass

    def clear_range(self, start: 'Address', end: 'Address') -> None:
        """Clears all associated values in the given range."""
        pass

    def clear_all(self) -> None:
        """Clears all values."""
        pass

    def is_empty(self) -> bool:
        """Returns true if this storage has no associated values for any address"""
        return False  # implement this method in your subclass

    def set_language(
            self,
            translator: 'LanguageTranslator',
            map_reg: 'Register',
            monitor: 'TaskMonitor'
    ) -> None:
        """Update table name and values to reflect new base register."""
        pass

    def get_value_range_containing(self, addr: 'Address') -> 'AddressRange':
        # implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def check_writable_state(self) -> None:
        if not self.is_writable():  # implement is_writable() method in your subclass
            raise ValueError("Adapter is not writable")
