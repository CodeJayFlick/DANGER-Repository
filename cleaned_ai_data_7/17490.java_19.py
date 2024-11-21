class Element:
    def __init__(self, reader: 'IPointReader', timeValuePair: 'TimeValuePair', priority: int):
        self.reader = reader
        self.timeValuePair = timeValuePair
        self.priority = priority

    @property
    def curr_time(self) -> int:
        return self.timeValuePair.timestamp

    @property
    def curr_pair(self) -> 'TimeValuePair':
        return self.timeValuePair

    def has_next(self) -> bool:
        try:
            return self.reader.has_next_time_value_pair()
        except Exception as e:
            raise IOException(str(e))

    def next(self):
        try:
            self.timeValuePair = self.reader.next_time_value_pair()
        except Exception as e:
            raise IOException(str(e))

    def close(self):
        try:
            self.reader.close()
        except Exception as e:
            raise IOException(str(e))

    @property
    def reader(self) -> 'IPointReader':
        return self.reader

    @property
    def time_value_pair(self) -> 'TimeValuePair':
        return self.timeValuePair

    @property
    def priority(self) -> int:
        return self.priority
