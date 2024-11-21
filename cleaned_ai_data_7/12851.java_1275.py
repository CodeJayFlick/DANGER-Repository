class Location:
    INTERNALLY_DEFINED = Location("<internally defined>", 1)

    def __init__(self, filename: str, lineno: int):
        self.filename = filename
        self.lineno = lineno

    def __str__(self) -> str:
        return f"{self.filename}:{self.lineno}"
