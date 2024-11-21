class DbgConsoleOutputEvent:
    def __init__(self, mask: int, info: str):
        self.info = info
        self.mask = mask

    @property
    def output(self) -> str:
        return self.info

    @property
    def mask(self) -> int:
        return self.mask
