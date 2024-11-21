Here is the equivalent Python code:

```Python
import unittest
from io import BytesIO
from typing import Any

class ShowDevicesResult:
    def __init__(self, name: str, sg_name: str):
        self.name = name
        self.sg_name = sg_name

    @classmethod
    def deserialize(cls, byte_buffer: bytes) -> 'ShowDevicesResult':
        result = cls(*byte_buffer.decode().split(','))
        return result

    def serialize(self) -> BytesIO:
        output_stream = BytesIO()
        output_stream.write(f"{self.name},{self.sg_name}".encode())
        return output_stream


class TestShowDevicesResult(unittest.TestCase):

    def test_serialize(self):
        show_devices_result = ShowDevicesResult("root.sg1.d1", "root.sg1")
        
        byte_buffer = bytes(show_devices_result.serialize().getbuffer())

        result = ShowDevicesResult.deserialize(byte_buffer)

        self.assertEqual(result.name, "root.sg1.d1")
        self.assertEqual(result.sg_name, "root.sg1")


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation or JUnit framework. The above code uses the built-in `unittest` module to define test cases and run them.