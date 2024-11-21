class ExceptionBatchData:
    def __init__(self, exception):
        self.exception = exception

    def has_current(self):
        raise NotImplementedError("hasCurrent is not supported for ExceptionBatchData")

    def get_exception(self):
        return self.exception
