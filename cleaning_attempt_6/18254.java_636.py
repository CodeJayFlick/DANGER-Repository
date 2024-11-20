class GtEq:
    def __init__(self, value=None, filter_type=None):
        self.value = value
        self.filter_type = filter_type

    @staticmethod
    def get_serialize_id():
        return "GTEQ"

    def copy(self):
        return GtEq(value=self.value, filter_type=self.filter_type)

    def __str__(self):
        if isinstance(self.value, int) and self.filter_type == 'TIME_FILTER':
            return f"TIME >= {self.value}"
        else:
            return f"{self.filter_type} >= {self.value}"

    def satisfy_statistics(self, statistics):
        if self.filter_type == "TIME_FILTER":
            return self.value <= statistics.get_end_time()
        elif statistics.get_type() in ['TEXT', 'BOOLEAN']:
            return True
        else:
            return self.value <= statistics.get_max_value()

    def satisfy(self, time=None, value=None):
        v = time if self.filter_type == "TIME_FILTER" else value
        return self.value <= v

    def satisfy_start_end_time(self, start_time=None, end_time=None):
        if self.filter_type == "TIME_FILTER":
            time = self.value
            return time <= end_time
        else:
            return True

    def contain_start_end_time(self, start_time=None, end_time=None):
        if self.filter_type == "TIME_FILTER":
            time = self.value
            return start_time >= time
        else:
            return True


# Example usage:

gt_eq_filter = GtEq(value=10, filter_type="GTEQ")
print(gt_eq_filter)  # Output: GTEQ >= 10

statistics = {'end_time': 15}
result = gt_eq_filter.satisfy_statistics(statistics)
print(result)  # Output: True
