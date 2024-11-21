Here is the translation of the Java code to Python:
```python
import logging
from typing import List, Dict, Any

class RestorableTsFileIOWriter:
    def __init__(self, file: str) -> None:
        self.file = file
        self.out = FSFactoryProducer.get_file_output_factory().get_tsfile_output(file, True)
        if not os.path.exists(self.file):
            start_file()
            self.crashed = True
            self.can_write = True
            return

        try:
            reader = TsFileSequenceReader(self.file, False)
            truncated_size = reader.self_check(known_schemas, chunk_group_metadata_list, True)
            min_plan_index = reader.get_min_plan_index()
            max_plan_index = reader.get_max_plan_index()

            if truncated_size == TsFileCheckStatus.COMPLETE_FILE:
                self.crashed = False
                self.can_write = False
                out.close()
            elif truncated_size == TsFileCheckStatus.INCOMPATIBLE_FILE:
                out.close()
                raise NotCompatibleTsFileException(f"{self.file} is not in TsFile format.")
            else:
                self.crashed = True
                self.can_write = True
                if truncate:
                    out.truncate(truncated_size)

        except Exception as e:
            logging.error(str(e))

    @classmethod
    def get_writer_for_appending_data_on_completed_tsfile(cls, file: str) -> 'RestorableTsFileIOWriter':
        position = os.path.getsize(file)
        try:
            reader = TsFileSequenceReader(file, False)
            if reader.is_complete():
                reader.load_metadata_size()
                position = reader.get_file_metadata_pos()

        except Exception as e:
            logging.error(str(e))

        if position != os.path.getsize(file):
            try:
                channel = FileChannel.open(Paths.get(file), StandardOpenOption.WRITE)
                channel.truncate(position - 1)  # remove the last marker.
            except Exception as e:
                logging.error(str(e))
        return cls(file)

    def get_truncated_size(self) -> int:
        return self.truncated_size

    @property
    def known_schemas(self) -> Dict[str, Any]:
        return self._known_schemas

    def make_metadata_visible(self) -> None:
        newly_flushed_metadata_list = self.appended_row_metadata()
        if newly_flushed_metadata_list:
            for chunk_group_metadata in newly_flushed_metadata_list:
                row_meta_data_list = chunk_group_metadata.get_chunk_metadata_list()

                device = chunk_group_metadata.get_device()
                for chunk_meta_data in row_meta_data_list:
                    measurement_id = chunk_meta_data.get_measurement_uid()
                    if not self.metadatas_for_query.get(device):
                        self.metadatas_for_query[device] = {}
                    if not self.metadatas_for_query[device].get(measurement_id):
                        self.metadatas_for_query[device][measurement_id] = []
                    self.metadatas_for_query[device][measurement_id].append(chunk_meta_data)

    def has_crashed(self) -> bool:
        return self.crashed

    @property
    def metadatas_for_query(self) -> Dict[str, Dict[str, List[Any]]]:
        return self._metadatas_for_query

    def get_visible_metadata_list(self, device_id: str, measurement_id: str, data_type: Any) -> List[ChunkMetadata]:
        chunk_meta_data_list = []
        if self.metadatas_for_query.get(device_id):
            for chunk_meta_data in self.metadatas_for_query[device_id].get(measurement_id):
                # filter: if a device'measurement is defined as float type, and data has been persistent.
                # Then someone deletes the timeseries and recreate it with Int type. We have to ignore
                # all the stale data.
                if not (data_type is None or data_type == chunk_meta_data.get_data_type()):
                    continue

                chunk_meta_data_list.append(chunk_meta_data)

        return chunk_metadata_list

    def get_appended_row_metadata(self) -> List[ChunkGroupMetadata]:
        append = []
        if self.last_flushed_chunk_group_index < len(self.chunk_group_metadata_list):
            append.extend(self.chunk_group_metadata_list[self.last_flushed_chunk_group_index:])
            self.last_flushed_chunk_group_index = len(self.chunk_group_metadata_list)

        return append

    def add_schema(self, path: str, schema: Any) -> None:
        self._known_schemas[path] = schema

    @property
    def last_flushed_chunk_group_index(self) -> int:
        return self._last_flushed_chunk_group_index

    @property
    def min_plan_index(self) -> int:
        return self.min_plan_index

    @property
    def max_plan_index(self) -> int:
        return self.max_plan_index
```
Note that I've used Python's built-in `logging` module to handle logging, and the `@classmethod` decorator to define a class method. Additionally, I've replaced Java's `Map` with Python's `Dict`, and `List` with Python's `list`.