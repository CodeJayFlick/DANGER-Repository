class AuthException(Exception):
    def __init__(self, message=""):
        super().__init__(message)

    def __init__(self, message="", cause=None):
        if cause is None:
            super().__init__(message)
        else:
            super().__init__(message, cause)

    def __init__(self, cause):
        super().__init__(cause)
