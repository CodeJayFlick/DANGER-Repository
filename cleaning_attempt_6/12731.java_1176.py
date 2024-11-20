class TypeMismatchException(Exception):
    def __init__(self, message="Type is not supported."):
        super().__init__(message)
