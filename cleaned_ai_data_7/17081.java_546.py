class LoadFileException(Exception):
    def __init__(self, message=None, ts_status_code=TSStatusCode.LOAD_FILE_ERROR.value):
        super().__init__(message)
        self.ts_status_code = ts_status_code
