class LoaderOpinionException(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, message: str, cause=None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        else:
            super().__init__(message)

    def __init__(self, message: str) -> None:
        super().__init__(message)

    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
