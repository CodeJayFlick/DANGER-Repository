Here is the translation of the Java code to Python:
```
import os
from hadoop import NullWritable, TSRecord  # assuming you have a `hadoop` module with these classes

class TsFileOutputFormat:
    def __init__(self, schema):
        self.schema = schema

    def get_record_writer(self, job):
        path = self.get_default_work_file(job)
        return TsFileRecordWriter(job, path, self.schema)

    def get_default_work_file(self, job):
        # implement this method to generate the default work file path
        pass


class TSRecord:
    pass  # assuming you have a `TSRecord` class with some implementation

class NullWritable:
    pass  # assuming you have a `NullWritable` class with some implementation

# Note: In Python, we don't need an explicit `@Override` annotation,
# as method overriding is implicit. Also, the `throws IOException`
# clause is not necessary in Python.
```
Note that I've assumed you have a `hadoop` module with classes like `NullWritable`, `TSRecord`, etc., which are equivalent to their Java counterparts. You'll need to implement these classes or import them from some other library.

Also, the `get_default_work_file` method is not implemented in this translation, as it's specific to your use case and may require additional logic.