class FilteredBytesAndDisassembly:
    def __init__(self, filtered_bytes: list[str], disassembly: list[str]):
        self.filtered_bytes = filtered_bytes
        self.disassembly_string = disassembly

    @property
    def filtered_bytes(self) -> list[str]:
        return self.filtered_bytes

    @property
    def disassembly(self) -> list[str]:
        return self.disassembly_string
