class IoTDBException(Exception):
    def __init__(self, message: str, error_code: int, is_user_exception=False) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.is_user_exception = is_user_exception

    @property
    def is_user_exception(self) -> bool:
        return self._is_user_exception

    @is_user_exception.setter
    def is_user_exception(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise TypeError("is_user_exception must be a boolean")
        self._is_user_exception = value

    @property
    def error_code(self) -> int:
        return self._error_code

    @error_code.setter
    def error_code(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("error_code must be an integer")
        self._error_code = value
