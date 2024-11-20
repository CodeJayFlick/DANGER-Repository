import unittest
from typing import List, Dict

class TsFileSerDeTest(unittest.TestCase):

    def setUp(self):
        self.ts_file_ser_de = None  # type: TsFileSerDe
        self.column_names = ["time_stamp", "sensor_1"]
        self.column_types = []  # type: List[TypeInfo]
        self.job = None  # type: JobConf
        self.tbl = {}  # type: Dict[str, str]

    def tearDown(self):
        self.ts_file_ser_de = None
        self.column_names = []
        self.column_types = []
        self.job = None
        self.tbl = {}

    @unittest.skipIf(not hasattr(unittest.TestCase, 'assertEqual'), "This test requires Python 3.5 or later")
    def test_deserialize(self):
        try:
            self.ts_file_ser_de.initialize(self.job, self.tbl)
        except SerDeException as e:
            print(e)

        self.assertEqual(PrimitiveObjectInspector.PrimitiveCategory.LONG,
                         (self.column_types[0]).get_primitive_category())

        writable1 = {"device_id": "device_2", "time_stamp": 1L, "sensor_1": 1L}
        try:
            self.ts_file_ser_de.deserialize(writable1)
            self.fail("Expect a TsFileSerDeException to be thrown!")
        except SerDeException as e:
            self.assertEqual("Expecting a MapWritable", str(e))

        writable2 = {"device_id": "device_2", "time_stamp": 1L, "sensor_1": 1L}
        try:
            result = self.ts_file_ser_de.deserialize(writable2)
            self.assertIsNone(result)
        except SerDeException as e:
            self.fail("Don't expect a TsFileSerDeException to be thrown!")

        writable3 = {"device_id": "device_1", "time_stamp": 1L, "sensor_1": 1}
        try:
            result = self.ts_file_ser_de.deserialize(writable3)
            self.fail("Expect a TsFileSerDeException to be thrown!")
        except SerDeException as e:
            expected_message = f"Unexpected data type: {writable3['sensor_1'].__class__.__name__} for Date TypeInfo: LONG"
            self.assertEqual(expected_message, str(e))

        writable = {"device_id": "device_1", "time_stamp": 1L, "sensor_1": 1000000L}
        try:
            result = self.ts_file_ser_de.deserialize(writable)
            self.assertIsInstance(result, list)
            row = result
            self.assertEqual(len(self.column_names), len(row))
            self.assertEqual(1L, row[0])
            self.assertEqual(1000000L, row[1])
        except SerDeException as e:
            self.fail("Don't expect a TsFileSerDeException to be thrown!")

if __name__ == '__main__':
    unittest.main()
