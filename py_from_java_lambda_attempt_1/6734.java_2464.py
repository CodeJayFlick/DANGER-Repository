Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `object` type to represent Java's `ByteBlock`, `ProgramLocationPluginEvent`, and other types, since Python doesn't have direct equivalents. Additionally, I've kept the method signatures similar to the original code, but with some minor adjustments for Python syntax.

Also, keep in mind that this is a translation of the Java code to Python, not an implementation or execution of the code. The `EmptyByteBlockSet` class may need additional logic and functionality depending on its intended use case.