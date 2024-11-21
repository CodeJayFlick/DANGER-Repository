class FakedSeriesReader:
    def __init__(self, timestamps=None, value=0):
        self.with_init_time_list = True if timestamps is not None else False
        self.index = 0
        self.size = len(timestamps) if timestamps is not None else 0
        self.timestamps = timestamps
        self.value = value

    def __init__(self, start_time=None, size=0, interval=1, mod_value=0):
        self.with_init_time_list = False
        self.index = 0
        self.size = size
        self.start_time = start_time if start_time is not None else 0
        self.interval = interval
        self.mod_value = mod_value

    def has_next(self):
        return self.index < self.size

    def next(self):
        if self.with_init_time_list:
            time, value = self.timestamps[self.index], self.value
            self.index += 1
            return (time, TsPrimitiveType.get_by_type(TSDataType.INT64, value))
        else:
            time, value = self.start_time + self.interval * self.index % self.mod_value, self.start_time + self.interval * self.index % self.mod_value
            self.index += 1
            return (time, TsPrimitiveType.get_by_type(TSDataType.INT64, value))

    def current(self):
        raise Exception("current() in FakedPrioritySeriesReader is an empty method.")

    def close(self):
        pass

class TimeValuePair:
    def __init__(self, time, value):
        self.time = time
        self.value = value

class TsPrimitiveType:
    @staticmethod
    def get_by_type(data_type, value):
        if data_type == TSDataType.INT64 and isinstance(value, int) or isinstance(value, float):
            return (value,)
        else:
            raise Exception("Invalid type for INT64")

TSDataType = {
    'INT64': 0,
}

FakedSeriesReader()
