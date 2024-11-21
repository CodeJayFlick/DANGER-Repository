class DbgModelRuntimeError(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, message):
        super().__init__(message)
