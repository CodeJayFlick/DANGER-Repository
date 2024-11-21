Here is the translation of the Java code into Python:

```Python
import unittest
from typing import List

class TestMemUtils(unittest.TestCase):

    def test_get_record_size(self):
        self.assertEqual(12, MemUtils.get_record_size(TSDataType.INT32, 10, True))
        self.assertEqual(16, MemUtils.get_record_size(TSDataType.INT64, 10, True))
        self.assertEqual(12, MemUtils.get_record_size(TSDataType.FLOAT, 10.0, True))
        self.assertEqual(16, MemUtils.get_record_size(TSDataType.DOUBLE, 10.0, True))
        self.assertEqual(8, MemUtils.get_record_size(TSDataType.TEXT, "10", False))

    def test_get_record_size_with_insert_plan(self):
        device = PartialPath("root.sg.d1")
        measurements = ["s1", "s2", "s3", "s4", "s5"]
        data_types: List[int] = []
        size_sum = 0
        for dt in [TSDataType.INT32, TSDataType.INT64, TSDataType.FLOAT, TSDataType.DOUBLE, TSDataType.TEXT]:
            size_sum += 8 + dt.get_data_type_size()
        insert_plan = InsertTabletPlan(device, measurements, data_types)
        self.assertEqual(size_sum, MemUtils.get_record_size(insert_plan, 0, 1, False))

    def test_get_mem_size(self):
        total_size = 0
        device = "root.sg.d1"
        record = TSRecord(0, device)

        point1 = IntDataPoint("s1", 1)
        self.assertEqual(MemUtils.get_string_mem("s1") + 20, MemUtils.get_data_point_mem(point1))
        total_size += MemUtils.get_data_point_mem(point1)
        record.add_tuple(point1)

        point2 = LongDataPoint("s2", 1)
        self.assertEqual(MemUtils.get_string_mem("s2") + 24, MemUtils.get_data_point_mem(point2))
        total_size += MemUtils.get_data_point_mem(point2)
        record.add_tuple(point2)

        point3 = FloatDataPoint("s3", 1.0)
        self.assertEqual(MemUtils.get_string_mem("s3") + 20, MemUtils.get_data_point_mem(point3))
        total_size += MemUtils.get_data_point_mem(point3)
        record.add_tuple(point3)

        point4 = DoubleDataPoint("s4", 1.0)
        self.assertEqual(MemUtils.get_string_mem("s4") + 24, MemUtils.get_data_point_mem(point4))
        total_size += MemUtils.get_data_point_mem(point4)
        record.add_tuple(point4)

        point5 = BooleanDataPoint("s5", True)
        self.assertEqual(MemUtils.get_string_mem("s5") + 17, MemUtils.get_data_point_mem(point5))
        total_size += MemUtils.get_data_point_mem(point5)
        record.add_tuple(point5)

        point6 = StringDataPoint("s5", Binary.valueOf("123"))
        self.assertEqual(MemUtils.get_string_mem("s6") + 129, MemUtils.get_data_point_mem(point6))
        total_size += MemUtils.get_data_point_mem(point6)
        record.add_tuple(point6)

        total_size += 8 * len(record.data_point_list) + MemUtils.get_string_mem(device) + 16

        self.assertEqual(total_size, MemUtils.get_ts_record_mem(record))

    def test_bytes_cnt_to_str(self):
        r = "4 GB 877 MB 539 KB 903 B"
        self.assertEqual(r, MemUtils.bytes_cnt_to_str(5215121287))


if __name__ == '__main__':
    unittest.main()
```

Note: The above Python code is a direct translation of the Java code. However, it may not work as expected because some classes and methods in the original Java code are missing or have different implementations in Python.