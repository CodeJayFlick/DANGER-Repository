Here is the translation of the Java interface `ByteBlockSet` into a Python class:

```Python
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
```

Note that I used Python's type hinting to indicate the types of parameters and return values. However, these hints are not enforced at runtime; they serve only as documentation for other developers.

I also left out some methods with default implementations or no implementation at all (e.g., `get_blocks`, `dispose`). These should be implemented in your subclass according to its specific needs.