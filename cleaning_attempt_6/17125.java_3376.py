class UDFFailure(Exception):
    def __init__(self, message: str, cause=None) -> None:
        super().__init__(message)
        self.cause = cause
