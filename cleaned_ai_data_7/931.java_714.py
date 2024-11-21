class DebugHostMemory1:
    def read_bytes(self, context: object, location: str, buffer: bytes, bufferSize: int) -> int:
        pass  # implement this method in your subclass

    def write_bytes(self, context: object, location: str, buffer: bytes, bufferSize: int) -> int:
        pass  # implement this method in your subclass

    def read_pointers(self, context: object, location: str, count: int) -> tuple[int]:
        pass  # implement this method in your subclass

    def write_pointers(self, context: object, location: str, count: int) -> tuple[int]:
        pass  # implement this method in your subclass

    def get_display_string_for_location(self, context: object, location: str, verbose: bool) -> str:
        pass  # implement this method in your subclass
