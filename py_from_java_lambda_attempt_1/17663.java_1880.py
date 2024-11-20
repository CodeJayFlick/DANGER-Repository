Here's your Java code translated into Python:

```Python
import logging
from typing import List

class TsFileOnlineUpgradeTool:
    def __init__(self, resource_to_be_upgraded: 'TsFileResource') -> None:
        super().__init__(resource_to_be_upgraded, True)

    @staticmethod
    def upgrade_one_ts_file(resource_to_be_upgraded: 'TsFileResource', upgraded_resources: List['TsFileResource']) -> None:
        try:
            updater = TsFileOnlineUpgradeTool(resource_to_be_upgraded)
            updater.upgrade_file(upgraded_resources)
        except (IOException, WriteProcessException) as e2:
            raise IOException(f"TsFile upgrade process cannot proceed at position {updater.reader.position()} because: {e2.message}")

    def upgrade_file(self, upgraded_resources: List['TsFileResource']) -> None:
        if not self.file_check():
            return

        marker = self.reader.read_marker()
        while marker != MetaMarker.SEPARATOR:
            match marker:
                case MetaMarker.CHUNK_HEADER:
                    chunk_header_offset = self.reader.position() - 1
                    header = ((TsFileSequenceReaderForV2) self.reader).read_chunk_header()
                    data_size = header.get_data_size()
                    while data_size > 0:
                        page_header = ((TsFileSequenceReaderForV2) self.reader).read_page_header(header.get_data_type())
                        if not skip_reading_chunk or self.device_id is None:
                            # a new Page
                            ((TsFileSequenceReaderForV2) self.reader).read_compressed_page(page_header)
                        else:
                            measurement_schema = UnaryMeasurementSchema(
                                header.get_measurement_id(),
                                header.get_data_type(),
                                header.get_encoding_type(),
                                header.get_compression_type()
                            )
                            data_in_chunk = []
                            page_headers_in_chunk = []
                            need_to_decode_info = []
                            while data_size > 0:
                                # a new Page
                                page_header = ((TsFileSequenceReaderForV2) self.reader).read_page_header(header.get_data_type())
                                if not skip_reading_chunk or self.device_id is None:
                                    header = ChunkHeader(
                                        measurement_schema,
                                        header.get_measurement_id(),
                                        header.get_data_type(),
                                        header.get_encoding_type()
                                    )
                                else:
                                    need_to_decode = check_if_need_to_decode(
                                        header.get_data_type(),
                                        header.get_encoding_type(),
                                        page_header,
                                        measurement_schema,
                                        self.device_id,
                                        chunk_header_offset
                                    )
                                    data_in_chunk.append(self.reader.read_compressed_page(page_header))
                                    page_headers_in_chunk.append(page_header)
                                    need_to_decode_info.append(need_to_decode)
                                data_size -= (
                                    int. bytes * 2 + 24 +
                                    (page_header.get_statistics().get_stats_size() - (header.get_data_type() == TSDataType.BOOLEAN ? 8 : 0)) +
                                    page_header.get_compressed_size()
                                )
                            self.rewrite_chunk(
                                self.device_id,
                                first_chunk_in_chunk_group,
                                measurement_schema,
                                page_headers_in_chunk,
                                data_in_chunk,
                                need_to_decode_info,
                                chunk_header_offset
                            )

                case MetaMarker.CHUNK_GROUP_HEADER:
                    if skip_reading_chunk:
                        skip_reading_chunk = False
                        chunk_group_footer = ((TsFileSequenceReaderForV2) self.reader).read_chunk_group_footer()
                        self.device_id = chunk_group_footer.get_device_id()
                        self.reader.position(first_chunk_position_in_chunk_group)
                    else:
                        end_chunk_group()
                        skip_reading_chunk = True

                case MetaMarker.VERSION:
                    version = ((TsFileSequenceReaderForV2) self.reader).read_version()
                    for ts_file_iowriter in partition_writer_map.values():
                        ts_file_iowriter.write_plan_indices()

            marker = self.reader.read_marker()

        # close upgraded tsFiles and generate resources for them
        for ts_file_iowriter in partition_writer_map.values():
            upgraded_resources.append(self.end_file_and_generate_resource(ts_file_iowriter))

    def upgrade_ts_file_name(self, old_ts_file_name: str) -> str:
        name = old_ts_file_name.split(TSFileConstant.TSFIlE_SUFFIX)
        return f"{name[0]}-0{TSFileConstant.TSFIlE_SUFFIX}"

    @staticmethod
    def check_if_need_to_decode(data_type: TSDataType, encoding: TSEncoding, page_header: PageHeader, schema: UnaryMeasurementSchema, device_id: str, chunk_header_offset: long) -> bool:
        return data_type == TSDataType.BOOLEAN or data_type == TSDataType.TEXT or (data_type == TSDataType.INT32 and encoding == TSEncoding.PLAIN)

    def decode_and_write_page(self, schema: UnaryMeasurementSchema, page_data: ByteBuffer, partition_chunk_writer_map: Map[Long, ChunkWriterImpl]) -> None:
        value_decoder.reset()
        page_reader = PageReaderV2(page_data, schema.get_type(), value_decoder, default_time_decoder, None)
        batch_data = page_reader.get_all_satisfied_page_data()
        self.rewrite_page_into_files(batch_data, schema, partition_chunk_writer_map)

    def file_check(self) -> bool:
        magic = self.reader.read_head_magic()
        if not magic == TSFileConfig.MAGIC_STRING:
            logging.error(f"the file's MAGIC STRING is incorrect, file path: {self.reader.get_file_name()}")
            return False

        version_number = ((TsFileSequenceReaderForV2) self.reader).read_version_number_v2()
        if not version_number == TSFileConfig.VERSION_NUMBER_V2:
            logging.error(f"the file's Version Number is incorrect, file path: {self.reader.get_file_name()}")
            return False

        tail_magic = self.reader.read_tail_magic()
        if not tail_magic == TSFileConfig.MAGIC_STRING:
            logging.error(f"the file is not closed correctly, file path: {self.reader.get_file_name()}")
            return False
        return True


class PageReaderV2:
    def __init__(self, page_data: ByteBuffer, data_type: TSDataType, value_decoder: 'ValueDecoder', default_time_decoder: 'DefaultTimeDecoder') -> None:
        self.page_data = page_data
        self.data_type = data_type
        self.value_decoder = value_decoder
        self.default_time_decoder = default_time_decoder

    def get_all_satisfied_page_data(self) -> BatchData:
        # your code here


class TsFileIOWriter:
    def write_plan_indices(self) -> None:
        # your code here


# Usage example:

resource_to_be_upgraded = 'your-tsfile-resource'
upgraded_resources = []

try:
    updater = TsFileOnlineUpgradeTool(resource_to_be_upgraded)
    updater.upgrade_file(upgraded_resources)

except (IOException, WriteProcessException):
    print("TsFile upgrade process failed")

finally:
    if reader is not None:
        reader.close()
```

This Python code assumes that you have the following classes:

- `TsFileResource`
- `PageReaderV2`
- `ChunkWriterImpl`
- `ValueDecoder`
- `DefaultTimeDecoder`
- `BatchData`