import io


class AssignPathManagedMergeReader:
    BATCH_SIZE = 4096

    def __init__(self, full_path: str, data_type):
        self.full_path = full_path
        self.data_type = data_type

    @property
    def managed_by_pool(self) -> bool:
        return False

    @managed_by_pool.setter
    def managed_by_pool(self, value: bool):
        self._managed_by_pool = value

    @property
    def has_remaining(self) -> bool:
        return False

    @has_remaining.setter
    def has_remaining(self, value: bool):
        self._has_remaining = value

    def __init_batch_data__(self) -> None:
        if not hasattr(self, 'batch_data'):
            self.batch_data = BatchData(data_type=self.data_type)

    def hasNextBatch(self) -> bool:
        if hasattr(self, 'batch_data') and self.batch_data is not None:
            return True
        self.__init_batch_data__()
        return self.batch_data is not None

    def nextBatch(self) -> io.BatchData:
        if not self.hasNextBatch():
            raise NoSuchElementException()
        ret = self.batch_data
        self.batch_data = None
        return ret


class BatchData(list):
    pass


class TimeValuePair:
    def __init__(self, timestamp: int, value: object):
        self.timestamp = timestamp
        self.value = value

    @property
    def get_timestamp(self) -> int:
        return self.timestamp

    @property
    def get_value(self) -> object:
        return self.value


class NoSuchElementException(Exception):
    pass
