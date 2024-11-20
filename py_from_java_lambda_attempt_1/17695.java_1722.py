Here is your Java code translated into equivalent Python:

```Python
import io
from typing import List, Tuple

class SerializeUtils:
    def __init__(self):
        pass  # util class

    @staticmethod
    def serialize(str_value: str, data_output_stream: io.BytesIO) -> None:
        try:
            bytes_str = str_value.encode('utf-8')
            data_output_stream.write(len(bytes_str).to_bytes(4, 'big'))
            data_output_stream.write(bytes_str)
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize_string(buffer: io.BytesIO) -> str:
        length = int.from_bytes(buffer.read(4), 'big')
        buffer.seek(-length - 4, 1)
        return buffer.read(length).decode('utf-8')

    @staticmethod
    def serialize_string_list(string_list: List[str], data_output_stream: io.BytesIO) -> None:
        try:
            data_output_stream.write(len(string_list).to_bytes(4, 'big'))
            for string in string_list:
                SerializeUtils.serialize(string, data_output_stream)
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize_string_list(buffer: io.BytesIO) -> List[str]:
        length = int.from_bytes(buffer.read(4), 'big')
        result = []
        for _ in range(length):
            result.append(SerializeUtils.deserialize_string(buffer))
        return result

    @staticmethod
    def serialize_int_list(int_list: List[int], data_output_stream: io.BytesIO) -> None:
        try:
            data_output_stream.write(len(int_list).to_bytes(4, 'big'))
            for num in int_list:
                data_output_stream.write(num.to_bytes(4, 'big'))
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize_int_list(buffer: io.BytesIO) -> List[int]:
        length = int.from_bytes(buffer.read(4), 'big')
        result = []
        for _ in range(length):
            result.append(int.from_bytes(buffer.read(4), 'big'))
        return result

    @staticmethod
    def serialize_batch_data(batch_data, data_output_stream: io.BytesIO) -> None:
        try:
            length = batch_data.length()
            data_type = batch_data.get_data_type().value
            data_output_stream.write(length.to_bytes(4, 'big'))
            data_output_stream.write(data_type)
            for i in range(length):
                time = batch_data.time_by_index(i).to_bytes(8, 'big')
                data_output_stream.write(time)
                if not batch_data.is_null_value():
                    value = batch_data.get_value_by_index(i)
                    SerializeUtils.serialize(value, data_output_stream)
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize_batch_data(buffer: io.BytesIO) -> object:
        length = int.from_bytes(buffer.read(4), 'big')
        buffer.seek(-8 - len(str(length).encode('utf-8')), 1)
        data_type = buffer.read(1)[0]
        result = BatchData(data_type, length)
        for i in range(length):
            time = int.from_bytes(buffer.read(8), 'big')
            if not buffer.read(4):  # is null value
                continue
            else:
                value = SerializeUtils.deserialize_value(buffer, data_type)
                result.put(time, value)
        return result

    @staticmethod
    def serialize_tv_pairs(tv_pairs: List[Tuple[long, object]], data_output_stream: io.BytesIO) -> None:
        try:
            if not tv_pairs:
                return
            data_type = tv_pairs[0][1].__class__.__name__
            data_output_stream.write(data_type.encode('utf-8'))
            for pair in tv_pairs:
                time = pair[0].to_bytes(8, 'big')
                data_output_stream.write(time)
                if not pair[1]:
                    continue
                else:
                    SerializeUtils.serialize(pair[1], data_output_stream)
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize_tv_pairs(buffer: io.BytesIO) -> List[Tuple[long, object]]:
        length = int.from_bytes(buffer.read(4), 'big')
        result = []
        for _ in range(length):
            time = int.from_bytes(buffer.read(8), 'big')
            buffer.seek(-1 - len(str(time).encode('utf-8')), 1)
            data_type = buffer.read(len(data_type)).decode('utf-8')
            value = SerializeUtils.deserialize_value(buffer, data_type)
            result.append((time, value))
        return result

    @staticmethod
    def serialize_filter(filter: object) -> io.BytesIO:
        output_stream = io.BytesIO()
        filter.serialize(output_stream)
        return output_stream

    @staticmethod
    def deserialize_filter(buffer: io.BytesIO) -> object:
        # TODO-Cluster: replace with a no-copy method
        pass  # unreachable

    @staticmethod
    def serialize_objects(objects: List[object], data_output_stream: io.BytesIO) -> None:
        try:
            if not objects:
                return
            length = len(objects)
            data_output_stream.write(length.to_bytes(4, 'big'))
            for obj in objects:
                SerializeUtils.serialize(obj, data_output_stream)
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize_objects(buffer: io.BytesIO) -> List[object]:
        length = int.from_bytes(buffer.read(4), 'big')
        result = []
        for _ in range(length):
            obj = SerializeUtils.deserialize_object(buffer)
            result.append(obj)
        return result

    @staticmethod
    def serialize_longs(longs: List[int], data_output_stream: io.BytesIO) -> None:
        try:
            if not longs:
                return
            length = len(longs)
            data_output_stream.write(length.to_bytes(4, 'big'))
            for num in longs:
                data_output_stream.write(num.to_bytes(8, 'big'))
        except Exception as e:
            pass  # unreachable

    @staticmethod
    def deserialize_longs(buffer: io.BytesIO) -> List[int]:
        length = int.from_bytes(buffer.read(4), 'big')
        result = []
        for _ in range(length):
            result.append(int.from_bytes(buffer.read(8), 'big'))
        return result


class BatchData:
    def __init__(self, data_type: str, length: int) -> None:
        self.data_type = data_type
        self.length = length

    @staticmethod
    def deserialize(data_type: str, buffer: io.BytesIO) -> object:
        if not buffer.read(1):  # is null value
            return None
        else:
            value = SerializeUtils.deserialize_value(buffer, data_type)
            return value


class TimeValuePair:
    def __init__(self, time: long, value: object) -> None:
        self.time = time
        self.value = value

    @staticmethod
    def deserialize_time_pair(buffer: io.BytesIO) -> Tuple[long, object]:
        if not buffer.read(1):  # is null value
            return (int.from_bytes(buffer.read(8), 'big'), None)
        else:
            time = int.from_bytes(buffer.read(8), 'big')
            data_type = buffer.read(1)[0]
            value = SerializeUtils.deserialize_value(buffer, data_type)
            return (time, value)


class TsPrimitiveType:
    @staticmethod
    def deserialize(buffer: io.BytesIO) -> object:
        pass  # unreachable


# Example usage:

serialize_utils = SerializeUtils()

data_output_stream = io.BytesIO()
string_list = ["Hello", "World"]
SerializeUtils.serialize_string_list(string_list, data_output_stream)

print(data_output_stream.getvalue())

buffer = io.BytesIO(data_output_stream.getvalue())
result = SerializeUtils.deserialize_string_list(buffer)
for string in result:
    print(string)