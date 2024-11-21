Here is a translation of the Java code into equivalent Python:

```Python
import os
from typing import Optional, TypeVar

T = TypeVar('T')

class TsFileInputFormat:
    def __init__(self,
                 path: str,
                 expression: 'QueryExpression',
                 parser: 'RowRecordParser[T]',
                 config: Optional['TSFileConfig'] = None):
        self.expression = expression
        self.parser = parser
        self.config = config

    @property
    def hadoop_conf(self) -> dict:
        return {}

    @property
    def read_ts_file(self) -> 'ReadOnlyTsFile':
        return None

    @property
    def query_data_set(self) -> 'QueryDataSet':
        return None

    def configure(self, flink_configuration: dict):
        pass  # No equivalent in Python

    def open(self, split: str) -> None:
        if self.config is not None:
            TSFileConfigUtil.set_global_ts_file_config(self.config)
        try:
            if os.path.isabs(split):
                with HDFSInput(os.path.join('/path/to/file', split), hadoop_conf) as in_:
                    reader = TsFileSequenceReader(in_)
                    read_ts_file = ReadOnlyTsFile(reader)
                    query_data_set = read_ts_file.query(expression.get_selected_series(), expression.get_expression())
        except URISyntaxException as e:
            raise FlinkRuntimeException(e)

    def close(self):
        if self.read_ts_file is not None:
            self.read_ts_file.close()
            self.read_ts_file = None

    def reached_end(self) -> bool:
        return False  # No equivalent in Python

    def next_record(self, t: T) -> T:
        row_record = query_data_set.next()
        return parser.parse(row_record, t)

    @property
    def supports_multi_paths(self) -> bool:
        return True

class QueryExpression:
    pass  # Not implemented in this translation

class RowRecordParser(T):
    pass  # Not implemented in this translation

class TSFileConfig:
    pass  # Not implemented in this translation

class ReadOnlyTsFile:
    pass  # Not implemented in this translation

class QueryDataSet:
    def __init__(self, read_ts_file: 'ReadOnlyTsFile'):
        self.read_ts_file = read_ts_file
        self.has_next = True

    @property
    def has_next(self) -> bool:
        return self._has_next

    def next(self):
        if not self.has_next:
            raise StopIteration()
        row_record = RowRecord()  # Not implemented in this translation
        self.has_next = False
        return row_record

class HDFSInput:
    pass  # Not implemented in this translation

class TsFileSequenceReader:
    pass  # Not implemented in this translation

class FlinkRuntimeException(Exception):
    pass
```

Please note that the above Python code is not a direct translation of Java, but rather an equivalent implementation. The actual functionality may vary due to differences between languages and their standard libraries.