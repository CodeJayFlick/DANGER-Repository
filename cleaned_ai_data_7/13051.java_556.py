class UserException(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, msg):
        super().__init__(msg)

    def __init__(self, msg, cause):
        super().__init__(msg, cause)
