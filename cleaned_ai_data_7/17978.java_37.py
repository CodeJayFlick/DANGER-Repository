import unittest
from typing import List, Dict

class LocalIoTDBSinkTest(unittest.TestCase):

    def setUp(self):
        EnvironmentUtils.envSetUp()

    def tearDown(self):
        EnvironmentUtils.cleanEnv()

    def test_onEventUsingSingleSensorHandler(self):
        local_iotdb_handler = LocalIoTDBHandler()
        config = LocalIoTDBConfiguration("root.sg1.d1", ["s1"], [TSDataType.INT32])
        local_iotdb_handler.open(config)

        for i in range(10000):
            event = LocalIoTDBEvent(i, i)
            local_iotdb_handler.on_event(event)

        local_iotdb_handler.close()

    def test_onEventUsingMultiSensorsHandler(self):
        local_iotdb_handler = LocalIoTDBHandler()
        config = LocalIoTDBConfiguration("root.sg1.d1", ["s1", "s2", "s3", "s4", "s5", "s6"], [
            TSDataType.INT32, 
            TSDataType.INT64, 
            TSDataType.FLOAT, 
            TSDataType.DOUBLE, 
            TSDataType.BOOLEAN, 
            TSDataType.TEXT
        ])
        local_iotdb_handler.open(config)

        for i in range(10000):
            event = LocalIoTDBEvent(i, i, int(i), float(i), float(i), i % 2 == 0, str(i))
            local_iotdb_handler.on_event(event)

        local_iotdb_handler.close()

    def test_onEventWithWrongType1(self):
        try:
            local_iotdb_handler = LocalIoTDBHandler()
            config = LocalIoTDBConfiguration("root.sg1.d1", ["s1"], [TSDataType.INT32])
            local_iotdb_handler.open(config)

            event = LocalIoTDBEvent(0, Binary.valueOf(str(0)))
            local_iotdb_handler.on_event(event)
        except QueryProcessException:
            pass

    def test_onEventWithWrongType2(self):
        try:
            local_iotdb_handler = LocalIoTDBHandler()
            config = LocalIoTDBConfiguration("root.sg1.d1", ["s1"], [TSDataType.TEXT])
            local_iotdb_handler.open(config)

            event = LocalIoTDBEvent(0, str(0))
            local_iotdb_handler.on_event(event)
        except ClassCastException:
            pass

    def check_header(self, result_set_meta_data: ResultSetMetaData, expected_header_strings: str, expected_types: List[int]) -> None:
        expected_headers = [header.strip() for header in expected_header_strings.split(",")]
        expected_header_to_type_index_map = {expected_header: i for i, expected_header in enumerate(expected_headers)}

        for i in range(1, result_set_meta_data.getColumnCount()):
            type_index = expected_header_to_type_index_map.get(result_set_meta_data.getColumnName(i))
            self.assertIsNotNone(type_index)
            self.assertEqual(expected_types[type_index], result_set_meta_data.getColumnType(i))

if __name__ == "__main__":
    unittest.main()
