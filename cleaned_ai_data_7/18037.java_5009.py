class StatementExecutionException(Exception):
    def __init__(self, status=None, reason=None, cause=None):
        if status:
            message = f"{status.code}: {status.message}"
        elif reason:
            message = reason
        else:
            message = "Unknown error"
        super().__init__(message)
        self.status_code = status.code if status else None

    def get_status_code(self):
        return self.status_code
