import io

class FakedBatchReader:
    def __init__(self, timestamps):
        self.data = BatchData(TSDataType.INT32)
        for time in timestamps:
            self.data.put_int(time, 1)
        self.has_cached = True

    def has_next_batch(self):
        return self.has_cached

    def next_batch(self):
        if not (self.data and self.data.has_current()):
            raise IOError("no next batch")
        self.has_cached = False
        return self.data

    def close(self):
        pass


class BatchData:
    def __init__(self, data_type):
        # assuming TSDataType.INT32 is equivalent to int in Python
        self.data_type = data_type
        self.current_index = 0

    def put_int(self, value, count=1):
        raise NotImplementedError("put_int not implemented")

    def has_current(self):
        return False


class IOError(Exception):
    pass
