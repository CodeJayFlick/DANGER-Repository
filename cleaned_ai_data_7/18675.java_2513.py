class MessageData:
    def __init__(self):
        pass

    def __init__(self, m):
        self.set_message(m)

    @property
    def message(self):
        return self._message

    @message.setter
    def set_message(self, message):
        self._message = message
