Here is the translation of the Java code to Python:
```
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
```
Note that I've used Python's built-in `list` type to represent the Java `ArrayList`, and the `len()` function to get the size of the list. The rest of the code is straightforward translation from Java to Python.

Also, in the `sort_by_time_desc()` method, I'm using a lambda function as the key for sorting, which is equivalent to the Java comparator-based sort.