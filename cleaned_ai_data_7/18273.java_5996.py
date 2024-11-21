import io

class LeafNode:
    def __init__(self, reader):
        self.reader = reader
        self.cache_data = None
        self.has_cached = False
        self.cached_time = 0
        self.cached_value = None

    def has_next(self) -> bool:
        if self.has_cached:
            return True
        if self.cache_data and self.cache_data.has_current():
            self.cached_time = self.cache_data.current_time()
            self.cached_value = self.cache_data.current_value()
            self.has_cached = True
            return True
        while self.reader.has_next_batch():
            self.cache_data = self.reader.next_batch()
            if self.cache_data and self.cache_data.has_current():
                self.cached_time = self.cache_data.current_time()
                self.cached_value = self.cache_data.current_value()
                self.has_cached = True
                return True
        return False

    def next(self) -> int:
        if self.has_cached or self.has_next():
            self.has_cached = False
            self.cache_data.next()
            return self.cached_time
        raise io.IOException("no more data")

    def current_time_is(self, time: int) -> bool:
        return self.cached_time == time

    def current_value(self):
        return self.cached_value

    def get_type(self) -> str:
        return "LEAF"
