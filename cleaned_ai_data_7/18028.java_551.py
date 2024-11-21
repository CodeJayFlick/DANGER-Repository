class BatchExecutionException(Exception):
    def __init__(self, message=None, status_list=None):
        super().__init__()
        self.status_list = status_list
        if message:
            self.message = message

    @property
    def status_list(self):
        return self._status_list

    @status_list.setter
    def status_list(self, value):
        self._status_list = value
