import unittest
from datetime import datetime as dt

class RecordUtilsTest(unittest.TestCase):

    def setUp(self):
        self.schema = Schema()
        conf = TSFileDescriptor.getInstance().getConfig()
        for i in range(6):
            path = Path(f"d1", f"s{i}")
            schema.registerTimeseries(path, UnaryMeasurementSchema(f"s{i}", 
                TSDataType.INT32 if i < 3 else TSDataType.FLOAT if i == 3 else
                TSDataType.DOUBLE if i == 4 else TSDataType.BOOLEAN if i == 5 else TSDataType.TEXT,
                TSEncoding.valueOf(conf.getValueEncoder())))

    def testParseSimpleTupleRecordInt(self):
        test_string = "d1,1471522347000,s1,1"
        record = RecordUtils.parseSimpleTupleRecord(test_string, self.schema)
        self.assertEqual(dt(2016, 8, 24).timestamp(), record.time)
        self.assertEqual("d1", record.device_id)
        tuples = record.data_point_list
        self.assertEqual(1, len(tuples))
        tuple_ = tuples[0]
        self.assertEqual("s1", tuple_.measurement_id)
        self.assertEqual(TSDataType.INT32, tuple_.type)
        self.assertEqual(1, tuple_.value)

    def testParseSimpleTupleRecordNull(self):
        test_string = "d1,1471522347000,s1,1,,"
        record = RecordUtils.parseSimpleTupleRecord(test_string, self.schema)
        self.assertEqual(dt(2016, 8, 24).timestamp(), record.time)
        tuples = record.data_point_list
        self.assertEqual(1, len(tuples))
        tuple_ = tuples[0]
        self.assertEqual("s1", tuple_.measurement_id)
        self.assertEqual(TSDataType.INT32, tuple_.type)
        self.assertEqual(1, tuple_.value)

    def testParseSimpleTupleRecordAll(self):
        test_string = "d1,1471522347000,s1,1,s2,134134287192587,s3,1.4,s4,1.128794817,s5,true"
        record = RecordUtils.parseSimpleTupleRecord(test_string, self.schema)
        self.assertEqual(dt(2016, 8, 24).timestamp(), record.time)
        self.assertEqual("d1", record.device_id)
        tuples = record.data_point_list
        self.assertEqual(5, len(tuples))
        tuple_ = tuples[0]
        self.assertEqual("s1", tuple_.measurement_id)
        self.assertEqual(TSDataType.INT32, tuple_.type)
        self.assertEqual(1, tuple_.value)

    def testError(self):
        test_string = "d1,1471522347000,s1,1,s2,"
        record = RecordUtils.parseSimpleTupleRecord(test_string, self.schema)
        self.assertEqual(dt(2016, 8, 24).timestamp(), record.time)
        tuples = record.data_point_list
        self.assertEqual(1, len(tuples))
        tuple_ = tuples[0]
        self.assertEqual("s1", tuple_.measurement_id)
        self.assertEqual(TSDataType.INT32, tuple_.type)
        self.assertEqual(1, tuple_.value)

    def testErrorMeasurementAndTimeStamp(self):
        test_string = "d1,1471522347000,s1,1,s123,"
        record = RecordUtils.parseSimpleTupleRecord(test_string, self.schema)
        self.assertEqual(dt(2016, 8, 24).timestamp(), record.time)
        tuples = record.data_point_list
        self.assertEqual(1, len(tuples))
        tuple_ = tuples[0]
        self.assertEqual("s1", tuple_.measurement_id)
        self.assertEqual(TSDataType.INT32, tuple_.type)
        self.assertEqual(1, tuple_.value)

        test_string = "d1,dsjhk,s1,1,s123,"
        record = RecordUtils.parseSimpleTupleRecord(test_string, self.schema)
        self.assertEqual(-1, record.time)
        tuples = record.data_point_list
        self.assertEqual(0, len(tuples))

        test_string = "d1,1471522347000,s8,1"
        record = RecordUtils.parseSimpleTupleRecord(test_string, self.schema)
        self.assertEqual(dt(2016, 8, 24).timestamp(), record.time)
        tuples = record.data_point_list
        self.assertEqual(0, len(tuples))

if __name__ == '__main__':
    unittest.main()
