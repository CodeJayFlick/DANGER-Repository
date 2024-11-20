import io

class ManagedPriorityMergeReader:
    BATCH_SIZE = 4096

    def __init__(self, data_type):
        self.data_type = data_type
        self.managed_by_pool = False
        self.has_remaining = False
        self.batch_data = None

    @property
    def managed_by_query_manager(self):
        return self.managed_by_pool

    @managed_by_query_manager.setter
    def set_managed_by_query_manager(self, value):
        self.managed_by_pool = value

    @property
    def has_remaining_(self):
        return self.has_remaining

    @has_remaining_.setter
    def set_has_remaining_(self, value):
        self.has_remaining = value

    def hasNextBatch(self) -> bool:
        if self.batch_data is not None:
            return True
        self.construct_batch()
        return self.batch_data is not None

    def construct_batch(self) -> None:
        while self.hasNextTimeValuePair() and len(self.batch_data) < self.BATCH_SIZE:
            next_time_value = self.nextTimeValuePair()
            self.batch_data.put(next_time_value.timestamp, next_time_value.value)

    @property
    def has_next_time_value_pair(self):
        # TO DO: implement this method
        pass

    def next_batch(self) -> io.BatchData:
        if not self.hasNextBatch():
            raise NoSuchElementException()
        ret = self.batch_data
        self.batch_data = None
        return ret
