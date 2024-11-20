class ListDataSet:
    def __init__(self):
        self.records = []
        self.index = 0

    def has_next_without_constraint(self):
        return self.index < len(self.records)

    def next_without_constraint(self):
        result = self.records[self.index]
        self.index += 1
        return result

    def put_record(self, new_record):
        self.records.append(new_record)

    def sort_by_time_desc(self):
        self.records.sort(key=lambda x: x.get_timestamp(), reverse=True)

    def sort(self, comparator):
        self.records.sort(comparator)
