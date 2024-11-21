class TimeseriesMetadata:
    def __init__(self):
        self.time_series_metadata_type = None
        self.chunk_meta_data_list_data_size = 0
        self.measurement_id = ''
        self.data_type = None
        self.statistics = None
        self.modified = False
        self.is_seq = True

    def __init__(self, time_series_metadata_type, chunk_meta_data_list_data_size, measurement_id, data_type, statistics):
        self.time_series_metadata_type = time_series_metadata_type
        self.chunk_meta_data_list_data_size = chunk_meta_data_list_data_size
        self.measurement_id = measurement_id
        self.data_type = data_type
        self.statistics = statistics

    def deserialize_from(self, buffer, need_chunk_metadata=False):
        if not hasattr(self, 'chunk_metadata_list'):
            self.chunk_metadata_list = []
        
        self.time_series_metadata_type = buffer.read_byte()
        self.measurement_id = ReadWriteIOUtils.read_var_int_string(buffer)
        self.data_type = ReadWriteIOUtils.read_data_type(buffer)
        chunk_meta_data_list_data_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer)

        if need_chunk_metadata:
            while buffer.has_remaining():
                self.chunk_metadata_list.append(ChunkMetadata.deserialize_from(buffer, self))

    def serialize_to(self):
        byte_len = 0
        byte_len += ReadWriteIOUtils.write(self.time_series_metadata_type)
        byte_len += ReadWriteIOUtils.write_var(self.measurement_id)
        byte_len += ReadWriteIOUtils.write(self.data_type)
        byte_len += ReadWriteForEncodingUtils.write_unsigned_var_int(self.chunk_meta_data_list_data_size)

    def get_time_series_metadata_type(self):
        return self.time_series_metadata_type

    # ... and so on for the rest of your methods
