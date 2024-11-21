import logging

class CreateAlignedTimeSeriesPlan:
    def __init__(self):
        self.prefix_path = None
        self.measurements = []
        self.data_types = []
        self.encodings = []
        self.compressor = None
        self.alias_list = []

    def __init__(self, prefix_path, measurements, data_types, encodings, compressor, alias_list):
        super().__init__()
        self.prefix_path = prefix_path
        self.measurements = measurements
        self.data_types = data_types
        self.encodings = encodings
        self.compressor = compressor
        self.alias_list = alias_list

    @property
    def prefix_path(self):
        return self._prefix_path

    @prefix_path.setter
    def prefix_path(self, value):
        self._prefix_path = value

    @property
    def measurements(self):
        return self._measurements

    @measurements.setter
    def measurements(self, value):
        self._measurements = value

    @property
    def data_types(self):
        return self._data_types

    @data_types.setter
    def data_types(self, value):
        self._data_types = value

    @property
    def encodings(self):
        return self._encodings

    @encodings.setter
    def encodings(self, value):
        self._encodings = value

    @property
    def compressor(self):
        return self._compressor

    @compressor.setter
    def compressor(self, value):
        self._compressor = value

    @property
    def alias_list(self):
        return self._alias_list

    @alias_list.setter
    def alias_list(self, value):
        self._alias_list = value

    def __str__(self):
        return f"device_path: {self.prefix_path}, measurements: {', '.join(self.measurements)}, data_types: {', '.join(map(str, self.data_types))}, encodings: {', '.join(map(str, self.encodings))}, compression: {self.compressor}"

    def get_paths(self):
        paths = []
        for measurement in self.measurements:
            try:
                path = PartialPath(self.prefix_path.get_full_path(), measurement)
                paths.append(path)
            except IllegalPathException as e:
                logging.error("Failed to get paths of CreateAlignedTimeSeriesPlan.", e)

        return paths

    def serialize(self, stream):
        PhysicalPlanType.serialize(stream, 1)  # CREATE_ALIGNED_TIMESERIES
        bytes = self.prefix_path.get_full_path().encode()
        stream.write(len(bytes).to_bytes(4, 'big'))
        stream.write(bytes)
        
        ReadWriteIOUtils.write(len(self.measurements), stream)
        for measurement in self.measurements:
            ReadWriteIOUtils.write(measurement.encode(), stream)

        for data_type in self.data_types:
            stream.write(data_type.value.to_bytes(1, 'big'))

        for encoding in self.encodings:
            stream.write(encoding.value.to_bytes(1, 'big'))

        stream.write(self.compressor.value.to_bytes(1, 'big'))
        
        if self.alias_list is not None:
            stream.write(b'\x01')
            for alias in self.alias_list:
                ReadWriteIOUtils.write(alias.encode(), stream)
        else:
            stream.write(b'\x00')

    def serialize(self, buffer):
        buffer.put(int(1).to_bytes(4, 'big'))  # CREATE_ALIGNED_TIMESERIES
        bytes = self.prefix_path.get_full_path().encode()
        buffer.putInt(len(bytes))
        buffer.put(bytes)
        
        ReadWriteIOUtils.write(len(self.measurements), buffer)
        for measurement in self.measurements:
            ReadWriteIOUtils.write(measurement.encode(), buffer)

        for data_type in self.data_types:
            buffer.put(data_type.value.to_bytes(1, 'big'))

        for encoding in self.encodings:
            buffer.put(encoding.value.to_bytes(1, 'big'))

        buffer.put(self.compressor.value.to_bytes(1, 'big'))
        
        if self.alias_list is not None:
            buffer.put(b'\x01')
            for alias in self.alias_list:
                ReadWriteIOUtils.write(alias.encode(), buffer)
        else:
            buffer.put(b'\x00')

    def deserialize(self, buffer):
        length = int.from_bytes(buffer.read(4), 'big')
        bytes = bytearray(length)
        buffer.readinto(bytes)

        self.prefix_path = PartialPath(str(bytes))
        
        size = ReadWriteIOUtils.readInt(buffer)
        measurements = []
        for _ in range(size):
            measurement = ReadWriteIOUtils.readString(buffer).decode()
            measurements.append(measurement)

        data_types = []
        for _ in range(size):
            data_type = TSDataType(int.from_bytes(buffer.read(1), 'big'))
            data_types.append(data_type)
        
        encodings = []
        for _ in range(size):
            encoding = TSEncoding(int.from_bytes(buffer.read(1), 'big'))
            encodings.append(encoding)

        self.compressor = CompressionType(int.from_bytes(buffer.read(1), 'big'))

        if buffer.get() == 1:
            alias_list = []
            for _ in range(size):
                alias = ReadWriteIOUtils.readString(buffer).decode()
                alias_list.append(alias)
        
        index = int.from_bytes(buffer.read(8), 'big')
