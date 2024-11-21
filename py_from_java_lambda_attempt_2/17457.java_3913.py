Here is the translation of the Java code to Python:
```python
import os
from typing import List

class LineMerger:
    def __init__(self, query_id: int, tmp_file_path: str):
        self.tmp_file_path = tmp_file_path
        self.query_id = query_id

    def merge(self, priority_series_readers: List) -> IPointReader:
        from io import StringIO  # Python equivalent of Java's FileDeserializer/Serializer
        serializer = FixLengthTimeValuePairSerializer(StringIO(tmp_file_path))
        reader = PriorityMergeReader(priority_series_readers, 1)
        while reader.has_next_time_value_pair():
            serializer.write(reader.next_time_value_pair())
        reader.close()
        serializer.close()

        deserializer = FixLengthIExternalSortFileDeserializer(StringIO(tmp_file_path))
        QueryResourceManager.getInstance().register_temp_external_sort_file(query_id, deserializer)

        return deserializer

class IPointReader:
    pass  # Python equivalent of Java's interface; no implementation needed in this case

class PriorityMergeReader:
    def __init__(self, priority_series_readers: List, num_threads: int):
        self.priority_series_readers = priority_series_readers
        self.num_threads = num_threads

    def has_next_time_value_pair(self) -> bool:
        # implement the logic to check if there are more time value pairs in the readers
        pass  # no implementation needed for this example, just a placeholder

    def next_time_value_pair(self) -> tuple:  # Python equivalent of Java's TimeValuePair; return type is tuple
        # implement the logic to read the next time value pair from the readers
        pass  # no implementation needed for this example, just a placeholder

class FixLengthTimeValuePairSerializer:
    def __init__(self, file_like_object):
        self.file_like_object = file_like_object

    def write(self, time_value_pair: tuple) -> None:
        # implement the logic to serialize the time value pair and write it to the file
        pass  # no implementation needed for this example, just a placeholder

class FixLengthIExternalSortFileDeserializer:
    def __init__(self, file_like_object):
        self.file_like_object = file_like_object

    def read(self) -> tuple:  # Python equivalent of Java's TimeValuePair; return type is tuple
        # implement the logic to deserialize and read a time value pair from the file
        pass  # no implementation needed for this example, just a placeholder

class QueryResourceManager:
    @staticmethod
    def getInstance() -> 'QueryResourceManager':
        # implement the singleton pattern or other mechanism to get an instance of QueryResourceManager
        pass  # no implementation needed for this example, just a placeholder

    def register_temp_external_sort_file(self, query_id: int, deserializer) -> None:
        # implement the logic to register the temporary external sort file with the QueryResourceManager
        pass  # no implementation needed for this example, just a placeholder
```
Note that I've kept some parts of the code as placeholders (e.g., `pass` statements), since they require specific implementations depending on your use case.