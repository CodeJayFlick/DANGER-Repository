class IllegalPathException(Exception):
    def __init__(self, path: str) -> None:
        super().__init__(f"{path} is not a legal path")
        self.error_code = TSStatusCode.PATH_ILLEGAL.value
        self.is_user_exception = True

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{path} is not a legal path because {reason}")
        self.error_code = TSStatusCode.PATH_ILLEGAL.value
        self.is_user_exception = True


class TSStatusCode:
    PATH_ILLEGAL = 0x0001

IllegalPathException = type("IllegalPathException", (Exception,), {})
