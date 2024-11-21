class ByteBlockSet:
    def get_blocks(self):
        # implement this method in your subclass
        pass

    def get_plugin_event(self, source: str, block: 'ByteBlock', offset: int, column: int) -> 'ProgramLocationPluginEvent':
        # implement this method in your subclass
        pass

    def get_plugin_event_selection(self, source: str, selection: 'ByteBlockSelection') -> 'ProgramSelectionPluginEvent':
        # implement this method in your subclass
        pass

    def is_changed(self, block: 'ByteBlock', index: int, length: int) -> bool:
        # implement this method in your subclass
        return False  # default implementation returns False

    def notify_byte_editing(self, block: 'ByteBlock', index: int, old_value: bytes, new_value: bytes):
        # implement this method in your subclass
        pass

    def dispose(self):
        # implement this method in your subclass if needed
        pass

    def get_address_set(self, selection: 'ByteBlockSelection') -> set:
        # implement this method in your subclass
        return set()
