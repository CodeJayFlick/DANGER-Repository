Here is the translation of the Java code into Python:

```Python
class TestManagedSeriesReader:
    def __init__(self, batch_data):
        self.batch_data = batch_data
        self.managed_by_query_manager = False
        self.has_remaining = False
        self.batch_used = False

    @property
    def managed_by_query_manager(self):
        return self.managed_by_query_manager

    @managed_by_query_manager.setter
    def set_managed_by_query_manager(self, value):
        self.managed_by_query_manager = value

    @property
    def has_remaining(self):
        return self.has_remaining

    @has_remaining.setter
    def set_has_remaining(self, value):
        self.has_remaining = value

    def get_values_in_timestamps(self, timestamps, length):
        results = [None] * length
        for i in range(length):
            while self.batch_data.has_current():
                curr_time = self.batch_data.current_time()
                if curr_time == timestamps[i]:
                    results[i] = self.batch_data.current_value()
                    break
                elif curr_time > timestamps[i]:
                    results[i] = None
                    break
                self.batch_data.next()
        return results

    def has_next_batch(self):
        return not self.batch_used

    def next_batch(self):
        if self.batch_used:
            raise NoSuchElementException()
        self.batch_used = True
        return self.batch_data

    def close(self):
        pass


class BatchData:
    def __init__(self, values=None):
        self.values = values or []
        self.index = 0

    @property
    def has_current(self):
        return self.index < len(self.values)

    @property
    def current_time(self):
        if not self.has_current:
            raise NoSuchElementException()
        return None  # Replace with actual logic to get the time value

    @property
    def current_value(self):
        if not self.has_current:
            raise NoSuchElementException()
        return self.values[self.index]

    def next(self):
        if not self.has_current:
            raise NoSuchElementException()
        self.index += 1


class NoSuchElementException(Exception):
    pass
```

Note that Python does not have direct equivalents for Java's `@Override` and `package` statements. Also, the equivalent of Java's `Object[]` in Python is a list (`[None] * length`).