class TimeseriesMetadataV2:
    def __init__(self):
        pass

    @staticmethod
    def deserialize_from(buffer: bytes) -> 'TimeseriesMetadata':
        timeseries_metadata = {}
        timeseries_metadata['measurement_id'] = buffer.decode('utf-8').split('\0')[1]
        ts_data_type = int.from_bytes(buffer[buffer.index(b'\x00') + 1:buffer.index(b'\x00\x00')], byteorder='big')
        timeseries_metadata['ts_data_type'] = TSDataType().deserialize(ts_data_type)
        offset_of_chunk_meta_data_list = int.from_bytes(buffer[buffer.index(b'\x00\x00') + 2:], byteorder='big')
        data_size_of_chunk_meta_data_list = int.from_bytes(buffer[buffer.index(b'\x00\x00\x00') + 3:], byteorder='big')
        timeseries_metadata['statistics'] = StatisticsV2().deserialize(buffer, timeseries_metadata['ts_data_type'])
        return timeseries_metadata

class TSDataType:
    @staticmethod
    def deserialize(ts_data_type: int) -> 'TSDataType':
        # implement your logic here to handle different ts data types
        pass

class StatisticsV2:
    @staticmethod
    def deserialize(buffer: bytes, ts_data_type: int) -> 'StatisticsV2':
        # implement your logic here to handle statistics deserialization
        pass
