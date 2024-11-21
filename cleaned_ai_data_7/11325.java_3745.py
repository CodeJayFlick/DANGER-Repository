class RollbackException(Exception):
    def __init__(self, message=None, cause=None):
        if cause:
            super().__init__(str(message) + " (caused by: {})".format(str(cause)), cause)
        elif message:
            super().__init__(message)
        else:
            super().__init__()
