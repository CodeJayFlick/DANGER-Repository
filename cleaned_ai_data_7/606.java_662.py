class DbgCommandError(Exception):
    def __init__(self, message=None, cmd=None, info=None):
        if message:
            super().__init__(message)
        elif cmd and info:
            super().__init__(f"{cmd} caused '{info}'")
        else:
            raise ValueError("Either a message or command and information must be provided")

    def get_info(self):
        return self.info
