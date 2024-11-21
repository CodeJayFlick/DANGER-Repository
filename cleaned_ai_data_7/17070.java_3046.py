class ContinuousQueryException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.is_user_exception = True
