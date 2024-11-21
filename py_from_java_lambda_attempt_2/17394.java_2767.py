Here is the translation of the Java code to Python:
```python
import logging
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

class FileReaderManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.resource_logger = logging.getLogger("FileMonitor")
        self.closed_file_reader_map = defaultdict(dict)
        self.unclosed_file_reader_map = defaultdict(dict)
        self.closed_reference_map = defaultdict(int)
        self.unclosed_reference_map = defaultdict(int)
        self.executor_service = ThreadPoolExecutor(max_workers=1, name="open-files-manager")

    @classmethod
    def get_instance(cls):
        return cls._instance

    _instance = None

    def close_file_and_remove_reader(self, file_path: str) -> None:
        if file_path in self.closed_reference_map:
            del self.closed_reference_map[file_path]
        reader = self.closed_file_reader_map.pop(file_path)
        if reader is not None:
            try:
                reader.close()
            except Exception as e:
                self.logger.error(f"Error closing TsFileSequenceReader {file_path}: {e}")
        if file_path in self.unclosed_reference_map:
            del self.unclosed_reference_map[file_path]
        reader = self.unclosed_file_reader_map.pop(file_path)
        if reader is not None:
            try:
                reader.close()
            except Exception as e:
                self.logger.error(f"Error closing TsFileSequenceReader {file_path}: {e}")

    def clear_unused_files_in_fix_time(self) -> None:
        examine_period = IoTDBDescriptor.get_instance().get_config().get_cache_file_reader_clear_period()
        self.executor_service.schedule_at_fixed_rate(
            lambda: self._clear_map(),
            0,
            examine_period,
            "milliseconds"
        )

    def _clear_map(self) -> None:
        for file_path, reader in list(self.closed_file_reader_map.items()):
            if not self.closed_reference_map[file_path]:
                try:
                    reader.close()
                except Exception as e:
                    self.logger.error(f"Error closing TsFileSequenceReader {file_path}: {e}")
                del self.closed_file_reader_map[file_path]
                del self.closed_reference_map[file_path]

        for file_path, reader in list(self.unclosed_file_reader_map.items()):
            if not self.unclosed_reference_map[file_path]:
                try:
                    reader.close()
                except Exception as e:
                    self.logger.error(f"Error closing TsFileSequenceReader {file_path}: {e}")
                del self.unclosed_file_reader_map[file_path]
                del self.unclosed_reference_map[file_path]

    def get(self, file_path: str, is_closed: bool) -> "TsFileSequenceReader":
        reader_map = self.closed_file_reader_map if not is_closed else self.unclosed_file_reader_map
        if file_path not in reader_map:
            if len(reader_map) >= MAX_CACHED_FILE_SIZE:
                self.logger.warn(f"Query has opened {len(reader_map)} files")
            ts_file_reader = None
            # check if the file is old version
            if not is_closed:
                ts_file_reader = UnClosedTsFileReader(file_path)
            else:
                ts_file_reader = TsFileSequenceReader(file_path)
                if ts_file_reader.read_version_number() != TS_FILE_CONFIG_VERSION_NUMBER:
                    ts_file_reader.close()
                    ts_file_reader = TsFileSequenceReaderForV2(file_path)
                    if (ts_file_reader.read_version_number_v2() or
                            not isinstance(ts_file_reader, TsFileSequenceReaderForV2)):
                        raise IOException(f"The version of this TsFile is not correct")
            reader_map[file_path] = ts_file_reader
        return reader_map[file_path]

    def increase_file_reader_reference(self, ts_file: "TsFileResource", is_closed: bool) -> None:
        if not is_closed:
            self.unclosed_reference_map[ts_file.get_ts_file_path()] += 1
        else:
            self.closed_reference_map[ts_file.get_ts_file_path()] += 1

    def decrease_file_reader_reference(self, ts_file: "TsFileResource", is_closed: bool) -> None:
        if not is_closed and file_path in self.unclosed_reference_map:
            self.unclosed_reference_map[file_path] -= 1
        elif file_path in self.closed_reference_map:
            self.closed_reference_map[file_path] -= 1

    def close_and_remove_all_opened_readers(self) -> None:
        for file_path, reader in list(self.closed_file_reader_map.items()):
            try:
                reader.close()
            except Exception as e:
                self.resource_logger.error(f"{file_path} closedTsFileReader is closed: {e}")
            del self.closed_reference_map[file_path]
        for file_path, reader in list(self.unclosed_file_reader_map.items()):
            try:
                reader.close()
            except Exception as e:
                self.resource_logger.error(f"{file_path} unclosedTsFileReader is closed: {e}")
            del self.unclosed_reference_map[file_path]

    def contains(self, ts_file: "TsFileResource", is_closed: bool) -> bool:
        return (is_closed and file_path in self.closed_file_reader_map) or (
                not is_closed and file_path in self.unclosed_file_reader_map)

    @property
    def executor_service(self):
        return self._executor_service

    @executor_service.setter
    def executor_service(self, value: ThreadPoolExecutor):
        self._executor_service = value

    @property
    def instance(cls):
        if cls._instance is None:
            cls._instance = FileReaderManager()
        return cls._instance


class TsFileSequenceReaderForV2(TsFileSequenceReader):
    pass


MAX_CACHED_FILE_SIZE = 30000