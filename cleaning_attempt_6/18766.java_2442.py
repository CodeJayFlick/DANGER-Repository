class HttpClientReadTimeoutException(Exception):
    def __init__(self, message=None, cause=None):
        if message:
            super().__init__(message)
        elif cause:
            super().__init__(str(cause))
        else:
            super().__init__()
