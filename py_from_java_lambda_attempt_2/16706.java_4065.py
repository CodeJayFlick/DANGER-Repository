Here is the equivalent Python code:

```Python
import unittest
from mock import patch, Mock
from collections import defaultdict


class MultSeriesRawDataPointReaderTest(unittest.TestCase):

    @patch('org.apache.iotdb.tsfile.read.reader.IPointReader')
    def setUp(self, IPointReader):
        self.batch_data = {'TSDataType': 'DOUBLE', 'start_time': 0, 'end_time': 100}
        self.point_reader_map = defaultdict(dict)
        series_raw_data_batch_reader_mock = Mock()
        series_raw_data_batch_reader_mock.hasNextTimeValuePair.return_value = True
        time_value_pair = (self.batch_data['start_time'], self.batch_data['TSDataType'])
        series_raw_data_batch_reader_mock.nextTimeValuePair.return_value = time_value_pair
        self.point_reader_map['root.a.b'] = series_raw_data_batch_reader_mock
        self.point_reader_map['root.a.c'] = series_raw_data_batch_reader_mock
        self.reader = MultSeriesRawDataPointReader(self.point_reader_map)


    def test_mult_series_reader(self):
        has_next = self.reader.has_next_time_value_pair('root.a.b')
        self.assertTrue(has_next)
        time_value_pair = self.reader.next_time_value_pair('root.a.b')
        self.assertEqual(0, time_value_pair[0])
        self.assertAlmostEqual(0.0, time_value_pair[1], 4)


if __name__ == '__main__':
    unittest.main()
```

Note: The Python code is not a direct translation of the Java code but rather an equivalent implementation in Python.