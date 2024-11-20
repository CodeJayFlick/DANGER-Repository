class BytesPcodeExecutorStateMixin:
    def from_constant(self, constant: int) -> object:
        pass  # Implement this method in your subclass

    def offset_to_long(self, offset: object) -> int:
        pass  # Implement this method in your subclass

    def to_bytes(self, val: object, size: int) -> bytes:
        pass  # Implement this method in your subclass

    def from_bytes(self, data: bytes) -> object:
        pass  # Implement this method in your subclass
