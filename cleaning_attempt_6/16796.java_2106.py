from typing import TypeVar, Generic

T = TypeVar('T')

class RowRecordParser(Generic[T], object):
    def parse(self, row_record: 'org.apache.iotdb.tsfile.read.common.RowRecord', reuse: T) -> T:
        # Your parsing logic here
        pass
