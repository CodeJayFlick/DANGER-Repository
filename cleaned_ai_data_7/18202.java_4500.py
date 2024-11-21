class VectorChunkMetadata:
    def __init__(self, time_chunk_metadata: 'IChunkMetadata', value_chunk_metadata_list: list):
        self.time_chunk_metadata = time_chunk_metadata
        self.value_chunk_metadata_list = value_chunk_metadata_list

    def get_statistics(self) -> Statistics:
        if len(self.value_chunk_metadata_list) == 1:
            return self.value_chunk_metadata_list[0].get_statistics()
        else:
            return self.time_chunk_metadata.get_statistics()

    def get_statistics(self, index: int) -> Statistics:
        return self.value_chunk_metadata_list[index].get_statistics()

    def is_modified(self) -> bool:
        return self.time_chunk_metadata.is_modified

    def set_modified(self, modified: bool):
        self.time_chunk_metadata.set_modified(modified)

    def is_seq(self) -> bool:
        return self.time_chunk_metadata.is_seq

    def set_seq(self, seq: bool):
        self.time_chunk_metadata.set_seq(seq)

    def get_version(self) -> int:
        return self.time_chunk_metadata.get_version()

    def set_version(self, version: int):
        self.time_chunk_metadata.set_version(version)

    def get_offset_of_chunk_header(self) -> int:
        return self.time_chunk_metadata.get_offset_of_chunk_header()

    def get_start_time(self) -> int:
        return self.time_chunk_metadata.get_start_time()

    def get_end_time(self) -> int:
        return self.time_chunk_metadata.get_end_time()

    def is_from_old_ts_file(self) -> bool:
        return False

    def get_chunk_loader(self) -> 'IChunkLoader':
        return self.time_chunk_metadata.get_chunk_loader()

    def need_set_chunk_loader(self) -> bool:
        if self.time_chunk_metadata.need_set_chunk_loader():
            return True
        else:
            for chunk_metadata in self.value_chunk_metadata_list:
                if chunk_metadata.need_set_chunk_loader():
                    return True
        return False

    def set_chunk_loader(self, chunk_loader: 'IChunkLoader'):
        self.time_chunk_metadata.set_chunk_loader(chunk_loader)
        for chunk_metadata in self.value_chunk_metadata_list:
            chunk_metadata.set_chunk_loader(chunk_loader)

    def set_file_path(self, file_path: str):
        self.time_chunk_metadata.set_file_path(file_path)
        for chunk_metadata in self.value_chunk_metadata_list:
            chunk_metadata.set_file_path(file_path)

    def set_closed(self, closed: bool):
        self.time_chunk_metadata.set_closed(closed)
        for chunk_metadata in self.value_chunk_metadata_list:
            chunk_metadata.set_closed(closed)

    def get_data_type(self) -> 'TSDataType':
        return self.time_chunk_metadata.get_data_type()

    def get_measurement_uid(self) -> str:
        return self.time_chunk_metadata.get_measurement_uid()

    def insert_into_sorted_deletions(self, start_time: int, end_time: int):
        self.time_chunk_metadata.insert_into_sorted_deletions(start_time, end_time)

    def get_delete_interval_list(self) -> list:
        return self.time_chunk_metadata.get_delete_interval_list()

    def serialize_to(self, output_stream: 'OutputStream', serialize_statistic: bool) -> None:
        raise NotImplementedError("VectorChunkMetadata doesn't support serial method")

    def get_mask(self) -> int:
        return 0

    def is_time_column(self) -> bool:
        return False

    def is_value_column(self) -> bool:
        return False

    def get_time_chunk(self) -> 'Chunk':
        try:
            return self.time_chunk_metadata.get_chunk_loader().load_chunk(time_chunk_metadata)
        except Exception as e:
            raise e

    def get_value_chunk_list(self) -> list:
        value_chunk_list = []
        for chunk_metadata in self.value_chunk_metadata_list:
            try:
                value_chunk_list.append(chunk_metadata.get_chunk_loader().load_chunk(chunk_metadata))
            except Exception as e:
                raise e
        return value_chunk_list

    def get_time_chunk_metadata(self):
        return self.time_chunk_metadata

    def get_value_chunk_metadata_list(self) -> list:
        return self.value_chunk_metadata_list


class Statistics:
    pass


class IChunkMetadata:
    pass


class ChunkLoader:
    pass


class OutputStream:
    pass
