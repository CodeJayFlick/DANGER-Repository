class TsFileDecodingException(Exception):
    def __init__(self, message=None, cause=None):
        if message is None:
            super().__init__()
        else:
            super().__init__(message)
        if cause is not None:
            self.__cause__ = cause

serialVersionUID = -8632392900655017028L
