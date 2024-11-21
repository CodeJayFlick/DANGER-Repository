class UnaryLastCacheValue:
    INDEX_OPERATION_ON_MONAD_EXCEPTION = "Cannot operate data on any index but 0 on MonadLastCacheValue"

    def __init__(self, timestamp: int, value):
        self.timestamp = timestamp
        self.value = value

    @property
    def get_timestamp(self) -> int:
        return self.timestamp

    @get_timestamp.setter
    def set_timestamp(self, timestamp: int):
        self.timestamp = timestamp

    @property
    def get_value(self) -> object:
        return self.value

    @get_value.setter
    def set_value(self, value):
        self.value = value

    def get_timeValuePair(self) -> tuple:
        return (self.timestamp, self.value)

    def get_size(self) -> int:
        return 1

    def get_timestamp_at_index(self, index: int) -> int:
        if index == 0:
            return self.timestamp
        else:
            raise RuntimeError(self.INDEX_OPERATION_ON_MONAD_EXCEPTION)

    def set_timestamp_at_index(self, index: int, timestamp: int):
        if index == 0:
            self.set_timestamp(timestamp)
        else:
            raise RuntimeError(self.INDEX_OPERATION_ON_MONAD_EXCEPTION)

    def get_value_at_index(self, index: int) -> object:
        if index == 0:
            return self.value
        else:
            raise RuntimeError(self.INDEX_OPERATION_ON_MONAD_EXCEPTION)

    def set_value_at_index(self, index: int, value):
        if index == 0:
            self.set_value(value)
        else:
            raise RuntimeError(self.INDEX_OPERATION_ON_MONAD_EXCEPTION)

    def get_timeValuePair_at_index(self, index: int) -> tuple:
        if index != 0:
            raise RuntimeError(self.INDEX_OPERATION_ON_MONAD_EXCEPTION)
        elif self.value is None:
            return None
        else:
            return (self.timestamp, self.value)
