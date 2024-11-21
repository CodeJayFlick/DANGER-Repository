class Error:
    def __init__(self, error_message):
        self.message = error_message

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, value):
        self._message = value
