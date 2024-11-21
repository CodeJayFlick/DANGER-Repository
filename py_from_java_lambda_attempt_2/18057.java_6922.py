Here is the translation of the given Java code into equivalent Python:

```Python
import logging
from typing import List

class SessionUtils:
    logger = logging.getLogger(__name__)

    @staticmethod
    def get_time_buffer(tablet: dict) -> bytes:
        time_buffer = bytearray(0)
        for i in range(len(tablet['timestamps'])):
            time_buffer.extend(int.to_bytes(tablet['timestamps'][i], 8, 'big'))
        return bytes(time_buffer)

    @staticmethod
    def get_value_buffer(tablet: dict) -> bytes:
        value_buffer = bytearray(0)
        index_of_values = 0

        for schema in tablet.get('schemas', []):
            if isinstance(schema, dict):  # Assuming IMeasurementSchema is a dictionary here.
                SessionUtils._get_value_buffer_of_data_type(
                    schema['type'], tablet, index_of_values, value_buffer
                )
                index_of_values += 1

        for bit_map in tablet.get('bitMaps', []):
            if bit_map:
                column_has_null = not bit_map.is_all_unmarked()
                value_buffer.extend(int.to_bytes(column_has_null, 1, 'big'))
                if column_has_null:
                    bytes_ = bit_map.get_byte_array()
                    for j in range(len(tablet['rowSize']) // 4 + 1):
                        value_buffer.extend(bytes_[j].to_bytes(1, 'big'))

        return bytes(value_buffer)

    @staticmethod
    def _get_value_buffer_of_data_type(data_type: str, tablet: dict, i: int, buffer: bytearray) -> None:
        if data_type == 'INT32':
            for value in tablet['values'][i]:
                if (tablet.get('bitMaps', [])[i] is not None and
                        tablet['bitMaps'][i].is_marked(index)):
                    buffer.extend(int.to_bytes(Integer.MIN_VALUE, 4, 'big'))
                else:
                    buffer.extend(value.to_bytes(4, 'little'))

        elif data_type == 'INT64':
            for value in tablet['values'][i]:
                if (tablet.get('bitMaps', [])[i] is not None and
                        tablet['bitMaps'][i].is_marked(index)):
                    buffer.extend(int.to_bytes(Long.MIN_VALUE, 8, 'big'))
                else:
                    buffer.extend(value.to_bytes(8, 'little'))

        elif data_type == 'FLOAT':
            for value in tablet['values'][i]:
                if (tablet.get('bitMaps', [])[i] is not None and
                        tablet['bitMaps'][i].is_marked(index)):
                    buffer.extend(float.frombytes(bytearray([0x80]), 0, 4).to_bytes(4, 'little'))
                else:
                    buffer.extend(value.to_bytes(4, 'little'))

        elif data_type == 'DOUBLE':
            for value in tablet['values'][i]:
                if (tablet.get('bitMaps', [])[i] is not None and
                        tablet['bitMaps'][i].is_marked(index)):
                    buffer.extend(float.frombytes(bytearray([0x80]), 0, 8).to_bytes(8, 'little'))
                else:
                    buffer.extend(value.to_bytes(8, 'little'))

        elif data_type == 'BOOLEAN':
            for value in tablet['values'][i]:
                if (tablet.get('bitMaps', [])[i] is not None and
                        tablet['bitMaps'][i].is_marked(index)):
                    buffer.extend(int.to_bytes(0, 1, 'big'))
                else:
                    buffer.extend(value.to_bytes(1, 'little'))

        elif data_type == 'TEXT':
            for value in tablet['values'][i]:
                if (tablet.get('bitMaps', [])[i] is not None and
                        tablet['bitMaps'][i].is_marked(index)):
                    buffer.extend(int.to_bytes(-1, 4, 'big'))
                else:
                    buffer.extend(value.encode())

        else:
            raise ValueError(f"Data type {data_type} is not supported.")

    @staticmethod
    def parse_seed_node_urls(node_urls: List[str]) -> List[dict]:
        if node_urls is None:
            raise ValueError("nodeUrls is null")

        end_points_list = []
        for node_url in node_urls:
            end_point = SessionUtils._parse_node_url(node_url)
            end_points_list.append(end_point)

        return end_points_list

    @staticmethod
    def _parse_node_url(node_url: str) -> dict:
        parts = node_url.split(":")
        if len(parts) != 2:
            raise ValueError("NodeUrl Incorrect format")

        ip, port = parts[0], int(parts[1])
        return {"ip": ip, "port": port}
```

Please note that Python does not have direct equivalent of Java's `ByteBuffer` and `BitMap`. I've used Python's built-in data types like `bytearray`, `int.to_bytes()`, etc. to achieve similar functionality.