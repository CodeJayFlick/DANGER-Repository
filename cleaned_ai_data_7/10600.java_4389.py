class XmlParseException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, t):
        super().__init__(message, t)
