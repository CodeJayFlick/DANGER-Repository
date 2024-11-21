class DataTypeDependencyException(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, message):
        super().__init__(message)

    def __init__(self, cause):
        super().__init__(cause)

    def __init__(self, message, cause):
        super().__init__(message, cause)
