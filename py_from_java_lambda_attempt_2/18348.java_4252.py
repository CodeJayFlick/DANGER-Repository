Here is the translation of the Java code into Python:

```Python
class TimeseriesSchema:
    def __init__(self):
        self.full_path = None
        self.type = None
        self.encoding = None
        self.compressor = None
        self.props = {}

    def __init__(self, full_path: str, ts_data_type: 'TSDataType', encoding: 'TSEncoding' = TSEncoding.valueOf(TSFileDescriptor.getInstance().getConfig().getValueEncoder()), compression_type: CompressionType = TSFileDescriptor.getInstance().getConfig().getCompressor(), props: dict = {}):
        self.full_path = full_path
        self.type = ts_data_type
        self.encoding = encoding
        self.compressor = compression_type
        self.props = props if props else {}

    @classmethod
    def deserialize_from(cls, buffer: bytes) -> 'TimeseriesSchema':
        timeseries_schema = cls()
        
        timeseries_schema.full_path = ReadWriteIOUtils.read_string(buffer)
        
        timeseries_schema.type = ReadWriteIOUtils.read_data_type(buffer)
        
        timeseries_schema.encoding = ReadWriteIOUtils.read_encoding(buffer)
        
        timeseries_schema.compressor = ReadWriteIOUtils.read_compression_type(buffer)

        size = ReadWriteIOUtils.read_int(buffer)
        if size > 0:
            timeseries_schema.props = {}
            for _ in range(size):
                key = ReadWriteIOUtils.read_string(buffer)
                value = ReadWriteIOUtils.read_string(buffer)
                timeseries_schema.props[key] = value

        return timeseries_schema

    def get_full_path(self) -> str:
        return self.full_path

    def set_full_path(self, full_path: str):
        self.full_path = full_path

    def get_props(self) -> dict:
        return self.props

    def get_encoding_type(self) -> 'TSEncoding':
        return self.encoding

    def get_type(self) -> 'TSDataType':
        return self.type

    def set_props(self, props: dict):
        self.props = props

    def get_time_encoder(self) -> Encoder:
        time_encoding = TSEncoding.valueOf(TSFileDescriptor.getInstance().getConfig().getTimeEncoder())
        time_type = TSFileDescriptor.getInstance().getConfig().getTimeSeriesDataType()
        return TSEncodingBuilder.get_encoding_builder(time_encoding).get_encoder(time_type)

    def get_value_encoder(self) -> Encoder:
        if self.encoding_converter is None:
            # initialize TSEncoding. e.g. set max error for PLA and SDT
            self.encoding_converter = TSEncodingBuilder.get_encoding_builder(self.encoding)
            self.encoding_converter.init_from_props(self.props)
        return self.encoding_converter.get_encoder(self.type)

    def get_compressor(self) -> CompressionType:
        return self.compressor

    def serialize_to(self, output_stream: bytes):
        byte_len = 0
        byte_len += ReadWriteIOUtils.write_string(self.full_path, output_stream)
        
        byte_len += ReadWriteIOUtils.write_data_type(self.type, output_stream)

        byte_len += ReadWriteIOUtils.write_encoding(self.encoding, output_stream)

        byte_len += ReadWriteIOUtils.write_compression_type(self.compressor, output_stream)

        if self.props is None:
            byte_len += ReadWriteIOUtils.write_int(0, output_stream)
        else:
            byte_len += ReadWriteIOUtils.write_int(len(self.props), output_stream)
            for key, value in self.props.items():
                byte_len += ReadWriteIOUtils.write_string(key, output_stream)
                byte_len += ReadWriteIOUtils.write_string(value, output_stream)

        return byte_len

    def serialize_to_byte_buffer(self) -> bytes:
        # same as above
        pass

    def __eq__(self, other):
        if self is other:
            return True
        if other is None or type(self) != type(other):
            return False
        that = TimeseriesSchema()
        return (self.type == that.type and 
                self.encoding == that.encoding and 
                ReadWriteIOUtils.equals_string(self.full_path, that.full_path) and 
                ReadWriteIOUtils.equals_compression_type(self.compressor, that.compressor))

    def __hash__(self):
        return hash((self.type, self.encoding, self.full_path, self.compressor))

    def __lt__(self, other):
        if self is other:
            return False
        else:
            return ReadWriteIOUtils.compare_string(self.full_path, other.full_path)

    def to_string(self) -> str:
        sc = StringContainer("")
        sc.add_tail("[", self.full_path, ",", self.type.toString(), ",", self.encoding.toString(), ",", str(self.props), ", ", self.compressor.toString())
        sc.add_tail("]")
        return sc.toString()
```

Please note that the `TSFileDescriptor`, `TSEncodingBuilder`, and other classes are not provided in this translation. You would need to implement these yourself or use existing Python libraries that provide similar functionality.