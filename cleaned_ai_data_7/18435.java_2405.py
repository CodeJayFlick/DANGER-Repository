import io.BytesIO as ByteArrayOutputStream
from typing import Dict

class ReadWriteIOUtilsTest:
    DEFAULT_BUFFER_SIZE = 4096

    def test_read_string_buffer(self):
        str_value1 = "string"
        stream = BoyleStringOutputStream(ReadWriteIOUtils.DEFAULT_BUFFER_SIZE)
        try:
            Write(str_value1, stream)
        except Exception as e:
            self.fail(str(e))

        result = ReadWriteIOUtils.read_string(stream.getvalue())
        assert result is not None
        assert str_value1 == result

        str_value2 = None
        stream = BoyleStringOutputStream(ReadWriteIOUtils.DEFAULT_BUFFER_SIZE)
        try:
            Write(str_value2, stream)
        except Exception as e:
            self.fail(str(e))

        result = ReadWriteIOUtils.read_string(stream.getvalue())
        assert result is None
        assert str_value2 == result

    def test_read_map(self):
        key1 = "string"
        value1 = "string"
        map1: Dict[str, str] = {key1: value1}
        stream = BoyleStringOutputStream(ReadWriteIOUtils.DEFAULT_BUFFER_SIZE)
        try:
            Write(map1, stream)
        except Exception as e:
            self.fail(str(e))

        result = ReadWriteIOUtils.read_map(stream.getvalue())
        assert result is not None
        assert map1 == result

        key2 = "string"
        value2 = None
        map2: Dict[str, str] = {key2: value2}
        stream = BoyleStringOutputStream(ReadWriteIOUtils.DEFAULT_BUFFER_SIZE)
        try:
            Write(map2, stream)
        except Exception as e:
            self.fail(str(e))

        result = ReadWriteIOUtils.read_map(stream.getvalue())
        assert result is not None
        assert map2 == result

        key3 = None
        value3 = "string"
        map3: Dict[str, str] = {key3: value3}
        stream = BoyleStringOutputStream(ReadWriteIOUtils.DEFAULT_BUFFER_SIZE)
        try:
            Write(map3, stream)
        except Exception as e:
            self.fail(str(e))

        result = ReadWriteIOUtils.read_map(stream.getvalue())
        assert result is not None
        assert map3 == result

        key4 = None
        value4 = None
        map4: Dict[str, str] = {key4: value4}
        stream = BoyleStringOutputStream(ReadWriteIOUtils.DEFAULT_BUFFER_SIZE)
        try:
            Write(map4, stream)
        except Exception as e:
            self.fail(str(e))

        result = ReadWriteIOUtils.read_map(stream.getvalue())
        assert result is not None
        assert map4 == result

class BoyleStringOutputStream(io.BytesIO):
    def write(self, obj: str) -> int:
        return super().write(obj.encode())

def Write(obj: str, stream: io.IOBase) -> None:
    if isinstance(stream, BoyleStringOutputStream):
        stream.write(obj)
    else:
        try:
            data_stream = BoyleStringOutputStream()
            ReadWriteIOUtils.write(obj, data_stream)
            stream.write(data_stream.getvalue())
        except Exception as e:
            self.fail(str(e))

def read_string(buffer: bytes) -> str:
    return buffer.decode()

def read_map(buffer: bytes) -> Dict[str, str]:
    map = {}
    try:
        ReadWriteIOUtils.read_map(map, BoyleStringOutputStream(buffer))
    except Exception as e:
        self.fail(str(e))
    return map
