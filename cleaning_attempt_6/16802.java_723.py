import io
from typing import TypeVar, Generic

TSRecord = TypeVar('TSRecord')

class TSFileOutputFormat(Generic[T]):
    def __init__(self, path: str, schema: 'Schema', converter: 'TSRecordConverter[T]', config=None):
        self.converter = converter
        super().__init__(path, schema, config)

    @property
    def ts_record_collector(self) -> 'TSRecordCollector':
        return self._ts_record_collector

    @ts_record_collector.setter
    def ts_record_collector(self, value: 'TSRecordCollector'):
        self._ts_record_collector = value

class TSRecordConverter(Generic[T]):
    pass  # todo: implement this class in Python

class Schema:
    pass  # todo: implement this class in Python

class Writer:
    def write(self, ts_record: TSRecord) -> None:
        raise NotImplementedError('Writer must be implemented')

class FlinkRuntimeException(Exception):
    pass

class IOException(Exception):
    pass

class WriteProcessException(Exception):
    pass

class Collector(Generic[T]):
    def collect(self, value: T) -> None:
        raise NotImplementedError('Collector must be implemented')

    def close(self) -> None:
        pass  # todo: implement this method in Python


class TSRecordCollector(Collector[TSRecord]):
    def __init__(self):
        self.writer = Writer()

    def collect(self, ts_record: TSRecord) -> None:
        try:
            self.writer.write(ts_record)
        except (IOException, WriteProcessException as e):
            raise FlinkRuntimeException(e)

    def close(self) -> None:
        pass  # todo: implement this method in Python


class TSFileOutputFormat(Generic[T]):
    def __init__(self, path: str, schema: 'Schema', converter: 'TSRecordConverter[T]', config=None):
        self.converter = converter
        super().__init__(path, schema, config)

    @property
    def ts_record_collector(self) -> 'TSRecordCollector':
        return self._ts_record_collector

    @ts_record_collector.setter
    def ts_record_collector(self, value: 'TSRecordCollector'):
        self._ts_record_collector = value

    def open(self, task_number: int, num_tasks: int) -> None:
        super().open(task_number, num_tasks)
        self.converter.open(schema)

    def close(self) -> None:
        self.converter.close()
        super().close()

    def write_record(self, t: T) -> None:
        try:
            self.converter.convert(t, self.ts_record_collector)
        except FlinkRuntimeException as e:
            raise IOException(e.cause)

    @property
    def converter(self) -> 'TSRecordConverter[T]':
        return self._converter

    @converter.setter
    def converter(self, value: 'TSRecordConverter[T]'):
        self._converter = value


# todo: implement the missing classes and methods in Python
