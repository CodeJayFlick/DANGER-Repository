class ZooProviderNotFoundException(Exception):
    def __init__(self, message=""):
        if not message:
            message = "Zoo provider not found"
        super().__init__(message)
