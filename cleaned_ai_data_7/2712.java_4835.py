class ServiceConstructionException(Exception):
    def __init__(self, message: str, cause: Exception) -> None:
        super().__init__(message, cause)

    def unwrap(self, cls: type[Exception]) -> None:
        cause = self.__cause__
        if isinstance(cause, cls):
            raise cls(cause)
