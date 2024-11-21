class Message:
    def __init__(self, msg):
        self.msg = msg

    @property
    def message(self):
        return self.msg

    def __str__(self):
        return str(self.msg)
