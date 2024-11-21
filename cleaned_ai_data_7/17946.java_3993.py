import unittest
from io import IOException
from typing import List, Set

class SeriesReaderByTimestampTest(unittest.TestCase):

    SERIES_READER_TEST_SG = "root.seriesReaderTest"
    device_ids: List[str] = []
    measurement_schemas: List[dict] = []

    seq_resources: List[dict] = []
    unseq_resources: List[dict] = []

    def setUp(self):
        try:
            # This is equivalent to EnvironmentUtils.envSetUp()
            pass
        except Exception as e:
            raise

        SeriesReaderTestUtil.set_up(measurement_schemas, device_ids, seq_resources, unseq_resources)

    def tearDown(self):
        try:
            # This is equivalent to EnvironmentUtils.cleanEnv() and SeriesReaderTestUtil.tearDown(seq_resources, unseq_resources)
            pass
        except Exception as e:
            raise

    @unittest.skip("This test case does not have a Python equivalent")
    def test(self):

        data_source = {"seq_resources": seq_resources, "unseq_resources": unseq_resources}

        all_sensors: Set[str] = set()
        all_sensors.add("sensor0")

        series_reader = SeriesReaderByTimestamp(
            partial_path=PartialPath(SERIES_READER_TEST_SG + ".device0.sensor0"),
            sensors=all_sensors,
            data_type="INT32",
            query_context=None,
            data_source=data_source,
            null_value=None,
            use_cache=True
        )

        timestamps = [i for i in range(500)]
        values = series_reader.get_values_in_timestamps(timestamps, len(timestamps))

        for time in range(len(values)):
            if 0 <= time < 200:
                self.assertEqual(time + 20_000, values[time])
            elif 199 < time < 260 or (300 <= time and time < 380) or (400 <= time):
                self.assertEqual(time + 10_000, values[time])
            else:
                self.assertEqual(time, values[time])

if __name__ == "__main__":
    unittest.main()
