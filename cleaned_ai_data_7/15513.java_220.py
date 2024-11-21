class ModelException(Exception):
    def __init__(self, message=""):
        if not isinstance(message, str):
            raise TypeError("Message must be a string")
        super().__init__(message)

    @classmethod
    def from_message(cls, message):
        return cls(message)

    @classmethod
    def from_exception(cls, exception):
        return cls(str(exception))
