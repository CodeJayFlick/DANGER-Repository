class GdbCommandErrorEvent:
    def __init__(self, tail):
        super().__init__(tail)

    @classmethod
    def from_mi2(cls, tail):
        return cls(tail)

    @classmethod
    def from_message(cls, message):
        return cls(message.strip())

# Note: Python does not have a direct equivalent of Java's GdbParseError. You may want to create an exception class for this purpose.
