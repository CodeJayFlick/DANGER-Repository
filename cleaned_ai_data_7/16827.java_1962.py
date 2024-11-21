class HDFSTSRecord:
    def __init__(self):
        self.time = None
        self.device_id = None
        self.data_point_list = []

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        self._time = value

    @property
    def device_id(self):
        return self._device_id

    @device_id.setter
    def device_id(self, value):
        self._device_id = value

    @property
    def data_point_list(self):
        return self._data_point_list

    @data_point_list.setter
    def data_point_list(self, value):
        self._data_point_list = value

    def convert_to_ts_record(self):
        ts_record = TSRecord(self.time, self.device_id)
        ts_record.data_point_list = self.data_point_list
        return ts_record


class DataPoint:
    def __init__(self, measurement_id, data_type, value):
        self.measurement_id = measurement_id
        self.data_type = data_type
        self.value = value

    @property
    def measurement_id(self):
        return self._measurement_id

    @measurement_id.setter
    def measurement_id(self, value):
        self._measurement_id = value

    @property
    def data_type(self):
        return self._data_type

    @data_type.setter
    def data_type(self, value):
        self._data_type = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class TSRecord:
    def __init__(self, time, device_id):
        self.time = time
        self.device_id = device_id
        self.data_point_list = []

    @property
    def time(self):
        return self._time

    @time.setter
    def time(self, value):
        self._time = value

    @property
    def device_id(self):
        return self._device_id

    @device_id.setter
    def device_id(self, value):
        self._device_id = value

    @property
    def data_point_list(self):
        return self._data_point_list

    @data_point_list.setter
    def data_point_list(self, value):
        self._data_point_list = value


def write_to_file(hdfsts_record: HDFSTSRecord) -> None:
    with open('output.txt', 'wb') as f:
        f.write((hdfsts_record.time).to_bytes(8, byteorder='little'))
        device_id_len = len(hdfsts_record.device_id.encode())
        f.write(device_id_len.to_bytes(4, byteorder='little'))
        f.write(hdfsts_record.device_id.encode())

        data_point_count = len(hdfsts_record.data_point_list)
        f.write(data_point_count.to_bytes(4, byteorder='little'))

        for data_point in hdfsts_record.data_point_list:
            if isinstance(data_point.value, bool):
                f.write((1).to_bytes(1, byteorder='little'))
                f.write(int(data_point.value).to_bytes(4, byteorder='little'))
            elif isinstance(data_point.value, int):
                f.write((2).to_bytes(1, byteorder='little'))
                f.write(int(data_point.value).to_bytes(4, byteorder='little'))
            elif isinstance(data_point.value, float):
                f.write((3).to_bytes(1, byteorder='little'))
                f.write(float_to_bytes(data_point.value))
            else:
                raise Exception("Unsupported data type")


def read_from_file() -> HDFSTSRecord:
    with open('output.txt', 'rb') as f:
        time = int.from_bytes(f.read(8), byteorder='little')
        device_id_len = int.from_bytes(f.read(4), byteorder='little')
        device_id = f.read(device_id_len).decode()

        data_point_count = int.from_bytes(f.read(4), byteorder='little')

        hdfsts_record = HDFSTSRecord()
        hdfsts_record.time = time
        hdfsts_record.device_id = device_id

        for _ in range(data_point_count):
            data_type = f.read(1)[0]
            if data_type == 0:
                measurement_id_len = int.from_bytes(f.read(4), byteorder='little')
                measurement_id = f.read(measurement_id_len).decode()
                value = bool(int.from_bytes(f.read(4), byteorder='little'))
            elif data_type == 1:
                measurement_id_len = int.from_bytes(f.read(4), byteorder='little')
                measurement_id = f.read(measurement_id_len).decode()
                value = int.from_bytes(f.read(4), byteorder='little')
            elif data_type == 2:
                measurement_id_len = int.from_bytes(f.read(4), byteorder='little')
                measurement_id = f.read(measurement_id_len).decode()
                value = float_from_bytes(f.read(8))
            else:
                raise Exception("Unsupported data type")

            hdfsts_record.data_point_list.append(DataPoint(measurement_id, data_type, value))

        return hdfsts_record


def float_to_bytes(value: float) -> bytes:
    # Convert the floating point number to a sequence of bytes
    # This is platform-dependent and may not work on all systems.
    import struct

    return struct.pack('>f', value)


def float_from_bytes(bytes: bytes) -> float:
    # Convert a sequence of bytes back into a floating point number
    # This is platform-dependent and may not work on all systems.
    import struct

    return struct.unpack('>f', bytes)[0]
