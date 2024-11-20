class ExceptionHandlerFrameException(Exception):
    def __init__(self, message=None, cause=None):
        if message is None and cause is None:
            super().__init__()
        elif message is not None and cause is None:
            super().__init__(message)
        elif message is None and cause is not None:
            super().__init__(cause)
        else:
            super().__init__(message, cause)

    def __str__(self):
        return self.args[0] if len(self.args) > 0 else "ExceptionHandlerFrameException"
