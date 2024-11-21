import io
from collections import defaultdict, deque
from typing import List, Dict, Tuple

class MetadataQuerierByFileImpl:
    def __init__(self, ts_file_reader):
        self.ts_file_reader = ts_file_reader
        self.file_metadata = ts_file_reader.read_file_metadata()
        self.chunk_meta_data_cache = LRUCache(CACHED_ENTRY_NUMBER)

    def get_chunk_meta_data_list(self, path: Path) -> List[ChunkMetadata]:
        return list(self.chunk_meta_data_cache.get(path))

    def get_chunk_meta_data_map(self, paths: List[Path]) -> Dict[Path, List[ChunkMetadata]]:
        chunk_meta_datas = defaultdict(list)
        for path in paths:
            if not chunk_meta_datas[path].exists():
                chunk_meta_datas[path] = []
            chunk_meta_datas[path].extend(self.get_chunk_meta_data_list(path))
        return dict(chunk_meta_datas)

    def get_whole_file_metadata(self) -> TsFileMetadata:
        return self.file_metadata

    def load_chunk_meta_das(self, paths: List[Path]) -> None:
        device_measurements_map = defaultdict(set)
        for path in paths:
            if not device_measurements_map[path.device].add(path.measurement):
                continue
        temp_chunk_meta_datas = {}
        count = 0
        enough = False

        for selected_device, selected_measurements in device_measurements_map.items():
            timeseries_metadata_list = self.ts_file_reader.read_timeseries_metadata(selected_device, selected_measurements)
            chunk_metadata_list = []
            for timeseries_metadata in timeseries_metadata_list:
                chunk_metadata_list.extend(self.ts_file_reader.read_chunk_meta_data_list(timeseries_metadata))
            for chunk_metadata in chunk_metadata_list:
                current_measurement = chunk_metadata.measurement_uid
                if selected_measurements.contains(current_measurement):
                    path = Path(selected_device, current_measurement)
                    temp_chunk_meta_datas[path] = []
                    temp_chunk_meta_datas[path].append(chunk_metadata)
                    count += 1
                    if count == CACHED_ENTRY_NUMBER:
                        enough = True
                        break

        for entry in temp_chunk_meta_datas.items():
            self.chunk_meta_data_cache.put(entry[0], entry[1])

    def get_data_type(self, path: Path) -> TSDataType:
        chunk_metadata_list = self.ts_file_reader.get_chunk_metadata_list(path)
        if not chunk_metadata_list or len(chunk_metadata_list) == 0:
            return None
        return chunk_metadata_list[0].data_type

    def load_chunk_meta_data(self, path: Path) -> List[ChunkMetadata]:
        return self.ts_file_reader.get_chunk_metadata_list(path)

    def convert_space2_time_partition(
        self,
        paths: List[Path],
        space_partition_start_pos: int,
        space_partition_end_pos: int
    ) -> List[TimeRange]:
        time_ranges_in_candidates = []
        time_ranges_before_candidates = []

        device_measurements_map = defaultdict(set)
        for path in paths:
            device_measurements_map[path.device].add(path.measurement)

        for selected_device, selected_measurements in device_measurements_map.items():
            series_metadatas = self.ts_file_reader.read_chunk_metadata_in_device(selected_device)
            for measurement_uid, chunk_metadata_list in series_metadatas.items():
                if not selected_measurements.contains(measurement_uid):
                    continue
                for chunk_metadata in chunk_metadata_list:
                    location = check_locate_status(chunk_metadata, space_partition_start_pos, space_partition_end_pos)
                    if location == LocateStatus.after:
                        break
                    elif location == LocateStatus.in:
                        time_ranges_in_candidates.append(TimeRange(chunk_metadata.start_time, chunk_metadata.end_time))
                    else:
                        time_ranges_before_candidates.append(TimeRange(chunk_metadata.start_time, chunk_metadata.end_time))

        time_ranges_in = sorted(list(set(time_ranges_in_candidates)), key=lambda x: (x.start_time, x.end_time))
        if not time_ranges_in:
            return []

        time_ranges_before = sorted(list(set(time_ranges_before_candidates)), key=lambda x: (x.start_time, x.end_time))

        res_time_ranges = []
        for in_range in time_ranges_in:
            remains = [TimeRange(in_range.start_time + 1, end) for TimeRange in time_ranges_before]
            res_time_ranges.extend(remains)

        return res_time_ranges

    @staticmethod
    def check_locate_status(chunk_metadata: IChunkMetadata, space_partition_start_pos: int, space_partition_end_pos: int) -> LocateStatus:
        start_offset_of_chunk = chunk_metadata.offset_of_chunk_header
        if space_partition_start_pos <= start_offset_of_chunk < space_partition_end_pos:
            return LocateStatus.in
        elif start_offset_of_chunk < space_partition_start_pos:
            return LocateStatus.before
        else:
            return LocateStatus.after

    def clear(self) -> None:
        self.chunk_meta_data_cache.clear()
