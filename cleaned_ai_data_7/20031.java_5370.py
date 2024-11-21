class YggdrasilException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)

    def __init__(self, message: str, cause: Exception) -> None:
        super().__init__(f"{message}: {cause}")

    def __init__(self, cause: Exception) -> None:
        if cause is not None:
            super().__init__(f"{type(cause).__name__}{'' if cause.message is None else f": {cause.message}"}, cause)
