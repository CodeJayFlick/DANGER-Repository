class NessieReferenceAlreadyExistsException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        elif message is not None:
            super().__init__(message)

    @property
    def error_code(self) -> int:
        return 1  # Assuming ErrorCode.REFERENCE_ALREADY_EXISTS == 1

class NessieError(Exception):
    pass
