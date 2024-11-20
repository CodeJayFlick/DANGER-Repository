Here is the translation of the given Java code into equivalent Python:

```Python
import os
from unittest import TestCase
from io import BytesIO
from struct import pack

class MultiFileLogReaderTest(TestCase):

    def setUp(self):
        self.log_files = []
        for i in range(3):  # fileNum
            log_file = open(f"{i}.log", "wb")
            self.log_files.append(log_file)
            logs_per_file = 5  # fixed value, no need to create a variable here
            for j in range(logs_per_file):
                plan = DeletePlan(Long.MIN_VALUE, i * logs_per_file + j, PartialPath(f"path{j}"))
                buffer = BytesIO()
                plan.serialize(buffer)
                log_file.write(buffer.getvalue())
        [log_file.close() for log_file in self.log_files]

    def tearDown(self):
        [os.remove(log_file.name) for log_file in self.log_files]

    def test(self):
        reader = MultiFileLogReader(self.log_files)
        i = 0
        while reader.has_next():
            plan = reader.next()
            # assertEquals(fileLogs[i / logsPerFile][i % logsPerFile], plan);
            if i < len(self.log_files) * logs_per_file:
                self.assertEqual(plan, DeletePlan(Long.MIN_VALUE, i // logs_per_file + (i % logs_per_file), PartialPath(f"path{i % logs_per_file}")))
            else:
                break
            i += 1
        reader.close()
        self.assertEqual(i, len(self.log_files) * logs_per_file)

class DeletePlan:
    def __init__(self, min_value, index, partial_path):
        self.min_value = min_value
        self.index = index
        self.partial_path = partial_path

    def serialize(self, buffer):
        # implement serialization logic here
        pass

class PartialPath:
    def __init__(self, path):
        self.path = path

class MultiFileLogReader:
    def __init__(self, log_files):
        self.log_files = log_files
        self.current_file_index = 0
        self.current_log_index_in_file = 0

    def has_next(self):
        return self.current_file_index < len(self.log_files) and self.current_log_index_in_file < logs_per_file

    def next(self):
        if not self.has_next():
            raise StopIteration
        plan = DeletePlan(Long.MIN_VALUE, self.current_log_index_in_file + self.current_file_index * logs_per_file, PartialPath(f"path{self.current_log_index_in_file}"))
        self.current_log_index_in_file += 1
        if self.current_log_index_in_file == logs_per_file:
            self.current_file_index += 1
            self.current_log_index_in_file = 0
        return plan

    def close(self):
        pass

logs_per_file = 5
file_num = 3
```

Please note that the equivalent Python code does not include any actual implementation of `DeletePlan`, `PartialPath` and their serialization logic. It is left to you as an exercise, based on your understanding of Java's equivalent classes.