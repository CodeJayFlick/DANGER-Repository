class BTreeUserDataRecord:
    def __init__(self):
        self.unused = None

    def set_unused(self, unused: bytes) -> None:
        self.unused = unused

    def get_unused(self) -> bytes:
        return self.unused


def to_data_type(self) -> dict:
    return {"unused": self.unused}
