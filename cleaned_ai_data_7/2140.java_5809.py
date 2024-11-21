class DebuggerAbnormalModelClosedReason:
    def __init__(self, exc):
        self.exc = exc

    def has_exception(self):
        return True

    def is_client_initiated(self):
        return False

    def get_exception(self):
        return self.exc
