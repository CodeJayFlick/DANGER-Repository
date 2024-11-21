import io
from typing import Any

class FixLengthIExternalSortFileDeserializer:
    def __init__(self, tmp_file_path: str) -> None:
        self.tmp_file_path = tmp_file_path
        self.input_stream = io.BufferedReader(io.open(tmp_file_path, 'rb'))
        self.data_type = self.read_header()
        self.reader = self.set_reader(self.data_type)

    def has_next_time_value_pair(self) -> bool:
        return self.input_stream.tell() < self.input_stream.filesize()

    def next_time_value_pair(self) -> Any:
        if not self.has_next_time_value_pair():
            raise StopIteration
        return self.reader.read(self.input_stream)

    def close(self) -> None:
        try:
            self.input_stream.close()
        except Exception as e:
            print(f"Error closing file: {e}")
        finally:
            import os
            if not os.path.exists(self.tmp_file_path):
                return
            try:
                os.remove(self.tmp_file_path)
            except Exception as e:
                print(f"Error deleting tmp file: {e}")

    def read_header(self) -> Any:
        data_type = ReadWriteIOUtils.read_byte(self.input_stream)
        return TSDataType.deserialize(data_type)

    @property
    def tmp_file_path(self):
        return self._tmp_file_path

    @tmp_file_path.setter
    def tmp_file_path(self, value: str):
        self._tmp_file_path = value


class TimeValuePairReader:
    def read(self, input_stream: io.BufferedReader) -> Any:
        raise NotImplementedError("Must be implemented by subclass")


class BooleanReader(TimeValuePairReader):
    def __init__(self) -> None:
        super().__init__()
        self.timestamp_bytes = bytearray(8)
        self.value_bytes = bytearray(1)

    def read(self, input_stream: io.BufferedReader) -> Any:
        timestamp_length = input_stream.readinto(self.timestamp_bytes)
        if timestamp_length != 8:
            raise IOError(f"Expected {8} bytes but got {timestamp_length}")
        value_length = input_stream.readinto(self.value_bytes)
        if value_length != 1:
            raise IOError(f"Expected {1} byte but got {value_length}")
        return TimeValuePair(BytesUtils.bytes_to_long(self.timestamp_bytes), TsPrimitiveType.TsBoolean(BytesUtils.bytes_to_bool(self.value_bytes)))


class IntReader(TimeValuePairReader):
    def __init__(self) -> None:
        super().__init__()
        self.timestamp_bytes = bytearray(8)
        self.value_bytes = bytearray(4)

    def read(self, input_stream: io.BufferedReader) -> Any:
        timestamp_length = input_stream.readinto(self.timestamp_bytes)
        if timestamp_length != 8:
            raise IOError(f"Expected {8} bytes but got {timestamp_length}")
        value_length = input_stream.readinto(self.value_bytes)
        if value_length != 4:
            raise IOError(f"Expected {4} byte but got {value_length}")
        return TimeValuePair(BytesUtils.bytes_to_long(self.timestamp_bytes), TsPrimitiveType.TsInt(BytesUtils.bytes_to_int(self.value_bytes)))


class LongReader(TimeValuePairReader):
    def __init__(self) -> None:
        super().__init__()
        self.timestamp_bytes = bytearray(8)
        self.value_bytes = bytearray(8)

    def read(self, input_stream: io.BufferedReader) -> Any:
        timestamp_length = input_stream.readinto(self.timestamp_bytes)
        if timestamp_length != 8:
            raise IOError(f"Expected {8} bytes but got {timestamp_length}")
        value_length = input_stream.readinto(self.value_bytes)
        if value_length != 8:
            raise IOError(f"Expected {8} byte but got {value_length}")
        return TimeValuePair(BytesUtils.bytes_to_long(self.timestamp_bytes), TsPrimitiveType.TsLong(BytesUtils.bytes_to_long(self.value_bytes)))


class FloatReader(TimeValuePairReader):
    def __init__(self) -> None:
        super().__init__()
        self.timestamp_bytes = bytearray(8)
        self.value_bytes = bytearray(4)

    def read(self, input_stream: io.BufferedReader) -> Any:
        timestamp_length = input_stream.readinto(self.timestamp_bytes)
        if timestamp_length != 8:
            raise IOError(f"Expected {8} bytes but got {timestamp_length}")
        value_length = input_stream.readinto(self.value_bytes)
        if value_length != 4:
            raise IOError(f"Expected {4} byte but got {value_length}")
        return TimeValuePair(BytesUtils.bytes_to_long(self.timestamp_bytes), TsPrimitiveType.TsFloat(BytesUtils.bytes_to_float(self.value_bytes)))


class DoubleReader(TimeValuePairReader):
    def __init__(self) -> None:
        super().__init__()
        self.timestamp_bytes = bytearray(8)
        self.value_bytes = bytearray(8)

    def read(self, input_stream: io.BufferedReader) -> Any:
        timestamp_length = input_stream.readinto(self.timestamp_bytes)
        if timestamp_length != 8:
            raise IOError(f"Expected {8} bytes but got {timestamp_length}")
        value_length = input_stream.readinto(self.value_bytes)
        if value_length != 8:
            raise IOError(f"Expected {8} byte but got {value_length}")
        return TimeValuePair(BytesUtils.bytes_to_long(self.timestamp_bytes), TsPrimitiveType.TsDouble(BytesUtils.bytes_to_double(self.value_bytes)))


class BinaryReader(TimeValuePairReader):
    def __init__(self) -> None:
        super().__init__()
        self.timestamp_bytes = bytearray(8)
        self.value_length_bytes = bytearray(4)
        self.value_bytes: bytes

    def read(self, input_stream: io.BufferedReader) -> Any:
        timestamp_length = input_stream.readinto(self.timestamp_bytes)
        if timestamp_length != 8:
            raise IOError(f"Expected {8} bytes but got {timestamp_length}")
        value_length_length = input_stream.readinto(self.value_length_bytes)
        if value_length_length != 4:
            raise IOError(f"Expected {4} byte but got {value_length_length}")
        length = BytesUtils.bytes_to_int(self.value_length_bytes)
        self.value_bytes = bytearray(length)
        read_length = input_stream.readinto(self.value_bytes)
        if read_length != length:
            raise IOError(f"Expected {length} bytes but got {read_length}")
        return TimeValuePair(BytesUtils.bytes_to_long(self.timestamp_bytes), TsPrimitiveType.TsBinary(Binary(BytesUtils.bytes_to_string(self.value_bytes))))
