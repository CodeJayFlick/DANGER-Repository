class IndexManagerException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, e):
        if isinstance(e, Exception):
            super().__init__(str(e))
        else:
            raise ValueError("Invalid exception type")
