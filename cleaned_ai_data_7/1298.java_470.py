class GdbTargetOutputEvent:
    def __init__(self, tail):
        super().__init__(tail)

# Define a custom exception class for parsing errors
class GdbParseError(Exception):
    pass
