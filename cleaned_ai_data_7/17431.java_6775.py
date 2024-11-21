class LastPointReader:
    def __init__(self):
        pass

    def __init__(self,
                 series_path: PartialPath,
                 data_type: TSDataType,
                 device_measurements: set[str],
                 context: QueryContext,
                 data_source: QueryDataSource,
                 query_time: int,
                 time_filter: Filter) -> None:
        self.series_path = series_path
        self.data_type = data_type
        self.device_measurements = device_measurements
        self.context = context
        self.data_source = data_source
        self.query_time = query_time
        self.time_filter = time_filter

    def read_last_point(self) -> TimeValuePair:
        result_point = retrieve_valid_last_point_from_seq_files()
        unpack_overlapped_unseq_files(result_point.timestamp)

        sorted_chunk_metadatas_list = sort_unseq_chunk_metadatas_by_endtime()
        while not sorted_chunk_metadatas_list.empty() and result_point.timestamp <= sorted_chunk_metadatas_list.peek().end_time:
            chunk_metadata = sorted_chunk_metadatas_list.poll()
            time_value_pair = get_chunk_last_point(chunk_metadata)
            if (time_value_pair.timestamp > result_point.timestamp or
                    (time_value_pair.timestamp == result_point.timestamp and should_update(cached_last_chunk, chunk_metadata))):
                cached_last_chunk = chunk_metadata
                result_point = time_value_pair

        return result_point

    def retrieve_valid_last_point_from_seq_files(self) -> TimeValuePair:
        seq_file_resources = self.data_source.get_seq_resources()
        last_point = TimeValuePair(long_min_value(), None)
        for i in range(len(seq_file_resources) - 1, -1, -1):
            resource = seq_file_resources[i]
            timeseries_metadata = FileLoaderUtils.load_time_series_metadata(resource, self.series_path, self.context, self.time_filter, self.device_measurements)
            if timeseries_metadata is not None:
                if not timeseries_metadata.modified and endtime_contained_by_time_filter(timeseries_metadata.statistics):
                    return construct_last_pair(timeseries_statistics().get_end_time(), timeseries_statistics().get_last_value(), self.data_type)

        return last_point

    def unpack_overlapped_unseq_files(self, l_bound_time: int) -> None:
        unseq_file_resources = sort_un_seq_file_resources_in_decending_order(self.data_source.get_unseq_resources())
        while not unseq_file_resources.empty() and (l_bound_time <= unseq_file_resources.peek().get_end_time()):
            timeseries_metadata = FileLoaderUtils.load_time_series_metadata(unseq_file_resources.poll(), self.series_path, self.context, self.time_filter, self.device_measurements)
            if timeseries_metadata is None or not timeseries_metadata.modified and endtime_contained_by_time_filter(timeseries_statistics):
                continue
            unseq_timeseries_metadata_list.append(timeseries_metadata)
            l_bound_time = max(l_bound_time, timeseries_statistics().get_end_time())

    def get_chunk_last_point(self, chunk_metadata: IChunkMetadata) -> TimeValuePair:
        last_point = TimeValuePair(long_min_value(), None)
        if chunk_metadata is None:
            return last_point
        statistics = chunk_metadata.get_statistics()
        if not chunk_metadata.modified and endtime_contained_by_time_filter(statistics):
            return construct_last_pair(statistics().get_end_time(), statistics().get_last_value(), self.data_type)

    def should_update(self, cached_chunk: IChunkMetadata, new_chunk: IChunkMetadata) -> bool:
        return (new_chunk.get_version() > cached_chunk.get_version()) or \
               (new_chunk.get_version() == cached_chunk.get_version() and new_chunk.get_offset_of_chunk_header() > cached_chunk.get_offset_of_chunk_header())

    def sort_un_seq_file_resources_in_decending_order(self, ts_file_resources: list[TsFileResource]) -> PriorityQueue:
        unseq_ts_files_set = PriorityQueue()
        for resource in ts_file_resources:
            unseq_ts_files_set.put(resource)
        return unseq_ts_files_set

    def sort_unseq_chunk_metadatas_by_endtime(self) -> PriorityQueue:
        chunk_metadata_list = PriorityQueue()
        for timeseries_metadata in self.unseq_timeseries_metadata_list:
            if timeseries_metadata is not None:
                chunk_metadata_list.extend(timeseries_statistics().load_chunk_metadata_list())
        return chunk_metadata_list

    def endtime_contained_by_time_filter(self, statistics: Statistics) -> bool:
        if self.time_filter is None:
            return True
        return self.time_filter.contain_start_end_time(statistics.get_end_time(), statistics.get_end_time())

    def construct_last_pair(self, timestamp: int, value: object, data_type: TSDataType) -> TimeValuePair:
        return TimeValuePair(timestamp, TsPrimitiveType.get_by_type(data_type, value))
