class ExportInfo:
    def __init__(self, address: int, ordinal: int, name: str, comment: str, forwarded: bool):
        self.address = address
        self.ordinal = ordinal
        self.name = name
        self.comment = comment
        self.forwarded = forwarded

    @property
    def get_address(self) -> int:
        return self.address

    @property
    def get_ordinal(self) -> int:
        return self.ordinal

    @property
    def get_name(self) -> str:
        return self.name

    @property
    def get_comment(self) -> str:
        return self.comment

    @property
    def is_forwarded(self) -> bool:
        return self.forwarded

    def __str__(self):
        return f"{self.ordinal} {self.name} at 0x{self.address:x}"
