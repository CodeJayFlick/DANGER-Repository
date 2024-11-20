class BatchProcessException(Exception):
    def __init__(self, failing_status):
        super().__init__("Batch process failed: " + str(failing_status))
        self.failing_status = failing_status

    @property
    def failing_status(self):
        return self._failing_status

batch_process_exception = lambda failing_status: BatchProcessException(failing_status)
