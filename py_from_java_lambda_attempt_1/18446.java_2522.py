Here is the translation of the Java code to Python:

```Python
import os
from typing import Dict

class ReadPageInMemTest:
    def __init__(self):
        self.file_path = "TsFileReadPageInMem"
        self.schema = None
        self.inner_writer = None
        self.page_size = 200
        self.chunk_group_size = 100000
        self.page_check_size_threshold = 1

    @staticmethod
    def get_schema() -> Dict[str, str]:
        schema = {}
        for i in range(4):
            path = f"root.car.d{i+1}"
            if i == 0:
                data_type = "INT32"
            elif i == 1:
                data_type = "INT64"
            elif i == 2:
                data_type = "FLOAT"
            else:
                data_type = "DOUBLE"
            schema[path] = f"s{i+1},{data_type}"
        return schema

    def setUp(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
        self.schema = self.get_schema()
        self.inner_writer = TsFileWriter(os.open(self.file_path, 'w'), self.schema)

    def tearDown(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def one_device_test(self):
        for i in range(1, 4):
            line = f"root.car.d1,{i},s1,1,s2,1,s3,0.1,s4,0.1"
            record = RecordUtils.parse_simple_tuple_record(line, self.schema)
            try:
                self.inner_writer.write(record)
            except (IOError, WriteProcessException) as e:
                print(e.message)
                assert False
        for i in range(4, 100):
            line = f"root.car.d1,{i},s1,1,s2,1,s3,0.1,s4,0.1"
            record = RecordUtils.parse_simple_tuple_record(line, self.schema)
            try:
                self.inner_writer.write(record)
            except (IOError, WriteProcessException) as e:
                print(e.message)
                assert False
        self.inner_writer.close()

    def multi_device_test(self):
        for i in range(1, 4):
            line = f"root.car.d1,{i},s1,1,s2,1,s3,0.1,s4,0.1"
            record = RecordUtils.parse_simple_tuple_record(line, self.schema)
            try:
                self.inner_writer.write(record)
            except (IOError, WriteProcessException) as e:
                print(e.message)
                assert False
        for i in range(1, 4):
            line = f"root.car.d2,{i},s1,1,s2,1,s3,0.1,s4,0.1"
            record = RecordUtils.parse_simple_tuple_record(line, self.schema)
            try:
                self.inner_writer.write(record)
            except (IOError, WriteProcessException) as e:
                print(e.message)
                assert False
        for i in range(4, 100):
            line = f"root.car.d1,{i},s1,1,s2,1,s3,0.1,s4,0.1"
            record = RecordUtils.parse_simple_tuple_record(line, self.schema)
            try:
                self.inner_writer.write(record)
            except (IOError, WriteProcessException) as e:
                print(e.message)
                assert False
        for i in range(4, 100):
            line = f"root.car.d2,{i},s1,1,s2,1,s3,0.1,s4,0.1"
            record = RecordUtils.parse_simple_tuple_record(line, self.schema)
            try:
                self.inner_writer.write(record)
            except (IOError, WriteProcessException) as e:
                print(e.message)
                assert False
        self.inner_writer.close()

class TsFileWriter:
    def __init__(self, file: int, schema: Dict[str, str]):
        pass

def main():
    test = ReadPageInMemTest()
    try:
        test.setUp()
        # Run tests here
        test.one_device_test()
        test.multi_device_test()
    finally:
        test.tearDown()

if __name__ == "__main__":
    main()
```

Please note that this is a direct translation of the Java code to Python, and it may not be optimal or idiomatic in terms of Pythonic coding practices.