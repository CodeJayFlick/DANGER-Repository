class NotCompatibleTsFileException(Exception):
    def __init__(self, message):
        super().__init__(message)

serialVersionUID = -3765109817887078265L  # Note: This is a long integer in Java, but it's not directly translatable to Python. It seems like this might be used for serialization purposes.
