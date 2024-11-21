class MessageData:
    def __init__(self, message):
        self.message = message

    @property
    def message(self):
        return self._message

    @classmethod
    def from_string(cls, message):
        return cls(message)
