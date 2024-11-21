Here is the translation of the Java code into Python:

```Python
import unittest
from collections import defaultdict

class SchemaBuilderTest(unittest.TestCase):

    def test_json_converter1(self):
        props = {"max_point_number": "3"}
        schema = {}
        timeseries_map = defaultdict(list)
        timeseries_map["d1/s4"] = ["s4", TSDataType.DOUBLE, TSEncoding.RLE, CompressionType.SNAPPY, props]
        timeseries_map["d1/s5"] = ["s5", TSDataType.INT32, TSEncoding.TS_2DIFF, CompressionType.UNCOMPRESSED, None]

        for path, desc in timeseries_map.items():
            schema[path] = {"desc": " ".join(desc)}

    def test_json_converter2(self):
        props = {"max_point_number": "3"}
        schema = {}
        template = defaultdict(dict)
        template["d1/s4"] = ["s4", TSDataType.DOUBLE, TSEncoding.RLE, CompressionType.SNAPPY, props]
        template["d1/s5"] = ["s5", TSDataType.INT32, TSEncoding.TS_2DIFF, CompressionType.UNCOMPRESSED, None]

        schema["template1"] = template
        schema["device/d1/template1"] = "template1"

    def test_json_converter3(self):
        props = {"max_point_number": "3"}
        schema = {}
        template = defaultdict(dict)
        template["d1/s4"] = ["s4", TSDataType.DOUBLE, TSEncoding.RLE, CompressionType.SNAPPY, props]
        template["d1/s5"] = ["s5", TSDataType.INT32, TSEncoding.TS_2DIFF, CompressionType.UNCOMPRESSED, None]

        schema["template1"] = template
        schema["device/d1/template1"] = "template1"
        schema["device/d1/template1/s6"] = ["s6", TSDataType.INT64, TSEncoding.RLE, CompressionType.SNAPPY, props]


if __name__ == "__main__":
    unittest.main()
```

Note that the Python code does not have direct equivalent of Java's `@Test` annotation. Instead, we use Python's built-in testing framework called `unittest`.