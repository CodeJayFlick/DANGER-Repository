class VectorSeriesAggregateReader:
    def __init__(self,
                 series_path: 'org.apache.iotdb.tsfile.file.metadata.VectorPartialPath',
                 all_sensors: set[str],
                 data_type: str,
                 context: 'org.apache.iotdb.db.query.context.QueryContext',
                 data_source: 'org.apache.iotdb.db.engine.querycontext.QueryDataSource',
                 time_filter: 'org.apache.iotdb.tsfile.read.filter.basic.Filter',
                 value_filter: 'org.apache.iotdb.tsfile.read.filter.basic.Filter',
                 file_filter: 'org.apache.iotdb.tsfile.read.filter.TsFileFilter',
                 ascending: bool):
        self.series_reader = SeriesReader(
            series_path,
            all_sensors,
            data_type,
            context,
            data_source,
            time_filter,
            value_filter,
            file_filter,
            ascending)
        self.sub_sensor_size = len(series_path.get_sub_sensors_list())

    def is_ascending(self) -> bool:
        return self.series_reader.get_order_utils().get_ascending()

    def has_next_file(self) -> bool:
        try:
            return self.series_reader.has_next_file()
        except IOException as e:
            raise

    def can_use_current_file_statistics(self) -> bool:
        file_statistics = current_file_statistics()
        if not series_reader.is_file_overlapped() and contained_by_time_filter(file_statistics):
            return True
        else:
            return False

    def current_file_statistics(self) -> 'org.apache.iotdb.tsfile.file.metadata.statistics.Statistics':
        try:
            return self.series_reader.current_file_statistics(cur_index)
        except IOException as e:
            raise

    def skip_current_file(self):
        self.series_reader.skip_current_file()

    def has_next_chunk(self) -> bool:
        try:
            return self.series_reader.has_next_chunk()
        except IOException as e:
            raise

    def can_use_current_chunk_statistics(self) -> bool:
        chunk_statistics = current_chunk_statistics()
        if not series_reader.is_chunk_overlapped() and contained_by_time_filter(chunk_statistics):
            return True
        else:
            return False

    def current_chunk_statistics(self) -> 'org.apache.iotdb.tsfile.file.metadata.statistics.Statistics':
        try:
            return self.series_reader.current_chunk_statistics(cur_index)
        except IOException as e:
            raise

    def skip_current_chunk(self):
        self.series_reader.skip_current_chunk()

    def has_next_page(self) -> bool:
        try:
            return self.series_reader.has_next_page()
        except IOException as e:
            raise

    def can_use_current_page_statistics(self) -> bool:
        page_statistics = current_page_statistics()
        if not series_reader.is_page_overlapped() and contained_by_time_filter(page_statistics):
            return True
        else:
            return False

    def current_page_statistics(self) -> 'org.apache.iotdb.tsfile.file.metadata.statistics.Statistics':
        try:
            return self.series_reader.current_page_statistics(cur_index)
        except IOException as e:
            raise

    def skip_current_page(self):
        self.series_reader.skip_current_page()

    def next_page(self) -> BatchData:
        return self.series_reader.next_page().flip()

    @staticmethod
    def contained_by_time_filter(statistics: 'org.apache.iotdb.tsfile.file.metadata.statistics.Statistics') -> bool:
        time_filter = series_reader.get_time_filter()
        if time_filter is None or time_filter.contain_start_end_time(statistics.get_start_time(), statistics.get_end_time()):
            return True
        else:
            return False

    def has_next_sub_series(self) -> bool:
        if self.cur_index < self.sub_sensor_size:
            return True
        else:
            self.reset_index()
            return False

    def next_series(self):
        self.cur_index += 1

    @property
    def cur_index(self) -> int:
        return self._cur_index

    def reset_index(self):
        self._cur_index = 0


class SeriesReader:

    # ... other methods and properties ...
