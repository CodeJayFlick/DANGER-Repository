class SyncConnectionException(Exception):
    def __init__(self, message=""):
        super().__init__(message)
        self.status_code = "SYNC_CONNECTION_EXCEPTION"

def __str__(self):
    return f"Sync Connection Exception: {super().__str__()}"
