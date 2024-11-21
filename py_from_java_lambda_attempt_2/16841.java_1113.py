Here is the equivalent Python code for the given Java file:

```Python
import logging
from hdfs3 import InsecureClient

class TSFHiveRecordWriter:
    def __init__(self, job_conf, path, schema):
        self.logger = logging.getLogger(__name__)
        self.writer = TsFileWriter(path, job_conf, schema)

    def write(self, writable):
        if not isinstance(writable, HDFSTSRecord):
            raise IOException(f"Expecting instance of HDFSTSRecord, but received {writable.__class__.__name__}")
        try:
            self.writer.write((HDFSTSRecord(writable)).convert_to_ts_record())
        except WriteProcessException as e:
            raise IOException(f"Write tsfile record error: {e}")

    def close(self):
        self.logger.info("Close the record writer")
        self.writer.close()

class TsFileWriter:
    def __init__(self, path, job_conf, schema):
        # Implement HDFSOutput and TsFileWriter logic here
        pass

class HDFSTSRecord:
    def convert_to_ts_record(self):
        # Implement conversion logic here
        pass

# Usage example:

job_conf = {}  # Replace with your JobConf object
path = 'hdfs://your-path'  # Replace with your HDFS path
schema = {}  # Replace with your schema definition

record_writer = TSFHiveRecordWriter(job_conf, path, schema)
record_writer.write(your_writable_object)  # Replace with the Writable object you want to write
record_writer.close()
```

Please note that this is a Python translation of the given Java code. The actual implementation may vary depending on your specific requirements and the libraries used in your project.