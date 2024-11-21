class DebugSymbolName:
    def __init__(self, name: str, offset: int):
        self.name = name
        self.offset = offset

    def __str__(self) -> str:
        return f"<{offset:016x}: {name}>"
