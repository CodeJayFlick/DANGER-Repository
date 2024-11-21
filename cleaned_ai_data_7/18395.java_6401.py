import os
from datetime import datetime as dt

class IMetadataQuerierByFileImplTest:
    FILE_PATH = 'outputDataFile'
    reader = None
    d1s6timeRangeList = []
    d2s1timeRangeList = []
    d1chunkGroupMetaDataOffsetList = []
    d2chunkGroupMetaDataOffsetList = []

    def before(self):
        os.system('generate_file 10000 1024 100')
        self.reader = TsFileSequenceReader(FILE_PATH)
        d1s6_list = self.reader.get_chunk_metadata_list(Path("d1", "s6"))
        for chunk_meta_data in d1s6_list:
            start_time, end_time = dt.fromtimestamp(chunk_meta_data.start_time), dt.fromtimestamp(chunk_meta_data.end_time)
            time_range = TimeRange(start_time, end_time)
            self.d1s6timeRangeList.append(time_range)
            offset_start_end = [chunk_meta_data.offset_of_chunk_header(), chunk_meta_data.offset_of_chunk_header() + len(chunk_meta_data.measurement_uid) + 8 + 2 + chunk_meta_data.statistics.serialized_size]
            self.d1chunkGroupMetaDataOffsetList.append(offset_start_end)

        d2s1_list = self.reader.get_chunk_metadata_list(Path("d2", "s1"))
        for chunk_meta_data in d2s1_list:
            start_time, end_time = dt.fromtimestamp(chunk_meta_data.start_time), dt.fromtimestamp(chunk_meta_data.end_time)
            time_range = TimeRange(start_time, end_time)
            self.d2s1timeRangeList.append(time_range)
            offset_start_end = [chunk_meta_data.offset_of_chunk_header(), chunk_meta_data.offset_of_chunk_header() + len(chunk_meta_data.measurement_uid) + 8 + 2 + chunk_meta_data.statistics.serialized_size]
            self.d2chunkGroupMetaDataOffsetList.append(offset_start_end)

    def after(self):
        if self.reader:
            self.reader.close()
        os.system('after')

class MetadataQuerierByFileImpl:
    def __init__(self, reader):
        self.reader = reader

    def convert_space2_time_partition(self, paths, start_pos, end_pos):
        time_ranges = []
        for path in paths:
            if path.startswith("d1"):
                d1s6_list = [time_range for time_range in self.d1s6timeRangeList]
                d1s6_list.sort(key=lambda x: (x.start_time))
                start_index, end_index = 0, len(d1s6_list) - 1
                while start_index <= end_index:
                    if start_pos >= d1s6_list[start_index].start_time and start_pos < d1s6_list[end_index].end_time:
                        time_ranges.append(TimeRange(start_pos, min(end_pos, d1s6_list[end_index].end_time)))
                        break
                    elif start_pos > d1s6_list[end_index].end_time:
                        end_index -= 1
                    else:
                        start_index += 1

                if not time_ranges and start_pos < d2s1timeRangeList[0].start_time:
                    return []

            elif path.startswith("d2"):
                # same logic as above, but for "d2"
                pass

        return time_ranges


class Path:
    def __init__(self, device, sensor):
        self.device = device
        self.sensor = sensor

    @property
    def value(self):
        return f"{self.device}.{self.sensor}"


class TimeRange:
    def __init__(self, start_time, end_time):
        self.start_time = start_time
        self.end_time = end_time

    def get_remains(self, before_candidates):
        remains = []
        for time_range in before_candidates:
            if not (time_range.start_time <= self.start_time and self.end_time <= time_range.end_time):
                remains.append(time_range)
        return remains


class TsFileSequenceReader:
    def __init__(self, file_path):
        self.file_path = file_path

    def get_chunk_metadata_list(self, path):
        # logic to read chunk metadata list
        pass

    def close(self):
        # logic to close the reader
        pass


# usage example
test = IMetadataQuerierByFileImplTest()
test.before()

metadata_querier_by_file_impl = MetadataQuerierByFileImpl(test.reader)

paths = [Path("d1", "s6"), Path("d2", "s1")]
start_pos, end_pos = 0L, 0L
time_ranges = metadata_querier_by_file_impl.convert_space2_time_partition(paths, start_pos, end_pos)
print(time_ranges)


test.after()
