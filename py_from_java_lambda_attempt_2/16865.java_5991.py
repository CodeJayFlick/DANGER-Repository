Here is the equivalent Python code:

```Python
import unittest
from influxdb import Point

class InfluxLineParserTest(unittest.TestCase):

    def test_parse_to_point(self):
        records = [
            "student,name=xie,sex=m country=\"china\",score=87.0,tel=\"110\" 1635177018815000000",
            "student,name=xie,sex=m country=\"china\",score=87i,tel=990i 1635187018815000000",
            "cpu,name=xie country=\"china\",score=100.0 1635187018815000000"
        ]
        expected_length = len(records)
        for i in range(expected_length):
            self.assertEqual(records[i], InfluxLineParser.parse_to_point(records[i]).line_protocol())

    def test_parser_records_to_points(self):
        records = [
            "student,name=xie,sex=m country=\"china\",score=87.0,tel=\"110\" 1635177018815000000",
            "student,name=xie,sex=m country=\"china\",score=87i,tel=990i 1635187018815000000",
            "cpu,name=xie country=\"china\",score=100.0 1635187018815000000"
        ]
        expected_length = len(records)
        points = InfluxLineParser.parser_records_to_points('\n'.join(map(str, records)))
        for i in range(expected_length):
            self.assertEqual(records[i], str(points[i]))

if __name__ == '__main__':
    unittest.main()
```

Note: The `InfluxLineParser` class and its methods (`parse_to_point`, `parser_records_to_points`) are not defined here. You would need to implement these classes and their methods in your Python code, or use an existing library that provides similar functionality.