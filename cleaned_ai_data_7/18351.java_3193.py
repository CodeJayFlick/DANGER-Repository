import logging
from typing import Dict, Any

class TsFileWriter:
    def __init__(self, file: str, schema: 'Schema', config: 'TSFileConfig'):
        self.schema = schema
        self.file_writer = None  # Initialize with None and set later
        self.pageSize = config.get_page_size_in_byte()
        self.chunk_group_size_threshold = config.get_group_size_in_byte()

    def register_schema_template(self, template_name: str, template: Dict[str, 'IMeasurementSchema']):
        self.schema.register_schema_template(template_name, template)

    def register_device(self, device_id: str, template_name: str):
        self.schema.register_device(device_id, template_name)

    def register_timeseries(self, path: Path, measurement_schema: 'IMeasurementSchema'):
        if self.schema.contains_timeseries(path):
            raise WriteProcessException("given timeseries has exists! " + path)
        self.schema.register_timeseries(path, measurement_schema)

    def check_is_time_series_exist(self, record: 'TSRecord') -> bool:
        group_writer = None
        for data_point in record.data_points:
            if not group_writers.get(record.device_id):
                group_writer = ChunkGroupWriterImpl(record.device_id)
                group_writers[record.device_id] = group_writer
            else:
                group_writer = group_writers[record.device_id]
            measurement_id = data_point.measurement_id
            path = Path(record.device_id, measurement_id)
            if self.schema.contains_timeseries(path):
                group_writer.try_add_series_writer(self.schema.get_series_schema(path), self.pageSize)
            elif self.schema.get_schema_templates() and len(self.schema.get_schema_templates()) == 1:
                template = self.schema.get_schema_templates().entry_set().next()[1]
                if template.get(measurement_id):
                    group_writer.try_add_series_writer(template[measurement_id], self.pageSize)
            else:
                raise NoMeasurementException("input path is invalid: " + measurement_id)

    def write(self, record: 'TSRecord') -> bool:
        self.check_is_time_series_exist(record)
        if not self.file_writer.can_write():
            return False
        group_writers[record.device_id].write(record.time, record.data_points)
        self.record_count += 1
        return check_memory_size_and_may_flush_chunks()

    def write(self, tablet: 'Tablet') -> bool:
        self.check_is_time_series_exist(tablet)
        if not self.file_writer.can_write():
            return False
        group_writers[tablet.prefix_path].write(tablet)
        self.record_count += tablet.row_size
        return check_memory_size_and_may_flush_chunks()

    def calculate_mem_size_for_all_group(self) -> int:
        mem_total_size = 0
        for group in group_writers.values():
            mem_total_size += group.update_max_group_mem_size()
        return mem_total_size

    def check_memory_size_and_may_flush_chunks(self) -> bool:
        if self.record_count >= self.record_count_for_next_mem_check:
            mem_size = self.calculate_mem_size_for_all_group()
            assert mem_size > 0
            if mem_size > self.chunk_group_size_threshold:
                logging.debug("start to flush chunk groups, memory space occupy: {}".format(mem_size))
                self.record_count_for_next_mem_check = self.record_count * self.chunk_group_size_threshold / mem_size
                return True
        return False

    def close(self) -> None:
        if not self.file_writer.can_write():
            logging.info("start to flush chunk groups")
            for device_id, group in group_writers.items():
                self.file_writer.start_chunk_group(device_id)
                pos = self.file_writer.get_pos()
                data_size = group.flush_to_file_writer(self.file_writer)
                if self.file_writer.get_pos() - pos != data_size:
                    raise IOException("Flushed data size is inconsistent with computation! Estimated: {}, Actual: {}".format(data_size, self.file_writer.get_pos() - pos))
                self.file_writer.end_chunk_group()
            reset()

    def get_iowriter(self) -> 'TsFileIOWriter':
        return self.file_writer

class ChunkGroupWriterImpl:
    # Implementation of IChunkGroupWriter
    pass

class Schema:
    # Implementation of IMeasurementSchema
    pass

class TSFileConfig:
    # Implementation of configuration for TsFile
    pass

class Path:
    def __init__(self, device_id: str, measurement_id: str):
        self.device_id = device_id
        self.measurement_id = measurement_id

class Tablet:
    def __init__(self, prefix_path: str, row_size: int):
        self.prefix_path = prefix_path
        self.row_size = row_size

class TSRecord:
    def __init__(self, time: Any, data_points: List['DataPoint']):
        self.time = time
        self.data_points = data_points

class DataPoint:
    # Implementation of datapoint for TSRecord
    pass

class WriteProcessException(Exception):
    pass

class NoMeasurementException(Exception):
    pass

class IOException(Exception):
    pass
