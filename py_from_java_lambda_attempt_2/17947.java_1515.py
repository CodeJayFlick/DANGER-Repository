Here is the translation of the Java code to Python:

```Python
import unittest
from typing import List, Set

class SeriesReaderTest(unittest.TestCase):

    SERIES_READER_TEST_SG = "root.seriesReaderTest"
    device_ids: List[str] = []
    measurement_schemas: List[dict] = []

    seq_resources: List[dict] = []
    unseq_resources: List[dict] = []

    def setUp(self):
        from series_reader_test_util import setUp
        setUp(measurement_schemas, device_ids, seq_resources, unseq_resources)

    def tearDown(self):
        from series_reader_test_util import tearDown
        tearDown(seq_resources, unseq_resources)

    def test_batch(self):
        all_sensors: Set[str] = {"sensor0"}
        series_reader = SeriesReader(
            PartialPath(f"{SERIES_READER_TEST_SG}.device0.sensor0"),
            all_sensors,
            TSDataType.INT32,
            EnvironmentUtils.TEST_QUERY_CONTEXT,
            seq_resources,
            unseq_resources,
            None, None, True
        )
        batch_reader = SeriesRawDataBatchReader(series_reader)
        count: int = 0
        while batch_reader.has_next_batch():
            batch_data = batch_reader.next_batch()
            self.assertEqual(TSDataType.INT32, batch_data.get_data_type())
            self.assertEqual(20, batch_data.length())
            for i in range(batch_data.length()):
                expected_time = i + 20 * count
                self.assertEqual(expected_time, batch_data.current_time())
                if expected_time < 200:
                    self.assertEqual(20000 + expected_time, batch_data.get_int())
                elif (expected_time >= 300 and expected_time < 380) or expected_time >= 400:
                    self.assertEqual(10000 + expected_time, batch_data.get_int())
                else:
                    self.assertEqual(expected_time, batch_data.get_int())
                batch_data.next()
            count += 1

    def test_point(self):
        all_sensors: Set[str] = {"sensor0"}
        series_reader = SeriesReader(
            PartialPath(f"{SERIES_READER_TEST_SG}.device0.sensor0"),
            all_sensors,
            TSDataType.INT32,
            EnvironmentUtils.TEST_QUERY_CONTEXT,
            seq_resources,
            unseq_resources,
            None, None, True
        )
        point_reader = SeriesRawDataPointReader(series_reader)
        expected_time: int = 0
        while point_reader.has_next_time_value_pair():
            time_value_pair = point_reader.next_time_value_pair()
            self.assertEqual(expected_time, time_value_pair.get_timestamp())
            value = time_value_pair.get_value().get_int()
            if expected_time < 200:
                self.assertEqual(20000 + expected_time, value)
            elif (expected_time >= 300 and expected_time < 380) or expected_time >= 400:
                self.assertEqual(10000 + expected_time, value)
            else:
                self.assertEqual(expected_time, value)
            expected_time += 1

    def test_desc_order(self):
        all_sensors: Set[str] = {"sensor0"}
        series_reader = SeriesReader(
            PartialPath(f"{SERIES_READER_TEST_SG}.device0.sensor0"),
            all_sensors,
            TSDataType.INT32,
            EnvironmentUtils.TEST_QUERY_CONTEXT,
            seq_resources,
            unseq_resources,
            None, None, False
        )
        point_reader = SeriesRawDataPointReader(series_reader)
        expected_time: int = 499
        while point_reader.has_next_time_value_pair():
            time_value_pair = point_reader.next_time_value_pair()
            self.assertEqual(expected_time, time_value_pair.get_timestamp())
            value = time_value_pair.get_value().get_int()
            if expected_time < 200:
                self.assertEqual(20000 + expected_time, value)
            elif (expected_time >= 300 and expected_time < 380) or expected_time >= 400:
                self.assertEqual(10000 + expected_time, value)
            else:
                self.assertEqual(expected_time, value)
            expected_time -= 1

if __name__ == '__main__':
    unittest.main()
```

Note that I have used Python's built-in `unittest` module to define the test cases. The tests are similar in structure and functionality to their Java counterparts.