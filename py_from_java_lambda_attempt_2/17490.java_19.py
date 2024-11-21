Here is the translation of the Java code to Python:
```
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
```
Note that I used Python's type hinting to indicate the types of the variables and method parameters. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I did not translate the `PriorityMergeReader.MERGE_READER_PRIORITY` enum constant from Java to Python, as there is no direct equivalent in Python. If you need to use this enum in your Python code, you may want to consider using a separate class or module to define it.