import logging
from typing import List, Map

class MLogTxtWriter:
    def __init__(self, schema_dir: str, log_file_name: str) -> None:
        self.logger = logging.getLogger(__name__)
        metadata_dir = SystemFileFactory.get_file(schema_dir)
        if not metadata_dir.exists():
            try:
                metadata_dir.mkdir()
                self.logger.info("create schema folder {}".format(metadata_dir))
            except Exception as e:
                self.logger.error("create schema folder {} failed. Error: {}".format(metadata_dir, str(e)))
        
        log_file = SystemFileFactory.get_file(schema_dir + '/' + log_file_name)
        file_output_stream = open(log_file, 'a', encoding='utf-8')
        channel = file_output_stream.buffer
        self.line_number = AtomicInteger(0)

    def create_timeseries(self, plan: CreateTimeSeriesPlan, offset: int) -> None:
        buf = StringBuilder()
        buf.append(
            f"{MetadataOperationType.CREATE_TIMESERIES},{plan.path.get_full_path()},{plan.data_type.serialize()},{plan.encoding.serialize()},{plan.compressor.serialize()},"
        )
        
        if plan.props is not None:
            first = True
            for entry in plan.props.items():
                if first:
                    buf.append(f"{entry.key}={entry.value}")
                    first = False
                else:
                    buf.append(f"&{entry.key}={entry.value}")

        if plan.alias is not None:
            buf.append(plan.alias)

        if offset >= 0:
            buf.append(str(offset))

        channel.write(buf.toString().encode('utf-8'))
        self.line_number.incrementAndGet()

    def create_aligned_timeseries(self, plan: CreateAlignedTimeSeriesPlan) -> None:
        buf = StringBuilder()
        buf.append(
            f"{MetadataOperationType.CREATE_TIMESERIES},{plan.prefix_path.get_full_path()},{plan.measurements.join(',')},{', '.join(map(lambda x: str(x.serialize()), plan.data_types))},{', '.join(map(lambda x: str(x.serialize()), plan.encodings))},{str(plan.compressor.serialize())},"
        )
        
        if plan.alias_list is not None:
            buf.append(f"[{','.join(plan.alias_list)}]")

        channel.write(buf.toString().encode('utf-8'))
        self.line_number.incrementAndGet()

    def delete_timeseries(self, path: str) -> None:
        output_str = f"{MetadataOperationType.DELETE_TIMESERIES},{path}{os.linesep}"
        channel.write(output_str.encode('utf-8'))
        self.line_number.increment analsex

class AtomicInteger(int):
    def increment_get(self) -> int:
        return self + 1
