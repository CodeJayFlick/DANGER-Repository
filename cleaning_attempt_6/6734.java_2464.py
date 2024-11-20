class EmptyByteBlockSet:
    def dispose(self):
        pass

    def get_blocks(self):
        return []

    def get_plugin_event_program_location(self, source: str, block: object, offset: int, column: int) -> object:
        return None

    def get_plugin_event_selection(self, source: str, selection: object) -> object:
        return None

    def is_changed(self, block: object, index: int, length: int) -> bool:
        return False

    def notify_byte_editing(self, block: object, index: int, old_value: bytes, new_value: bytes):
        pass

    def get_address_set(self, selection: object) -> object:
        return None
