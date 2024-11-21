class NessieConflictException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if not message:
            super().__init__("Conflict")
        else:
            super().__init__(message)
        
        self.status_code = 409

    @classmethod
    def from_error(cls, error):
        return cls(error.to_string())
