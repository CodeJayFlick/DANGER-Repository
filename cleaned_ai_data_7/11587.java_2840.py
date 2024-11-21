class MemoryFaultHandler:
    def uninitialized_read(self, address: int, size: int, buf: bytes, buf_offset: int) -> bool:
        """An attempt has been made to read uninitialized memory at the specified address."""
        return True  # Treat data as initialized

    def unknown_address(self, address: int, write: bool) -> bool:
        """Unable to translate the specified address"""
        return False  # Fault was not handled
