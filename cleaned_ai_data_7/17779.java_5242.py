import unittest
from datetime import timedelta

class MemTableFlushTaskTest(unittest.TestCase):

    def setUp(self):
        self.writer = None
        self.storage_group = "storage_group1"
        self.file_path = TestConstant.OUTPUT_DATA_DIR + "/testUnsealedTsFileProcessor.tsfile"
        self.mem_table = PrimitiveMemTable()
        self.start_time = 1
        self.end_time = 100

    def tearDown(self):
        if self.writer is not None:
            self.writer.close()

    @unittest.skipIf(TestConstant.OUTPUT_DATA_DIR == "", "Test data directory does not exist")
    def test_flush_mem_table(self):
        MemTableTestUtils.produce_data(
            mem_table=self.mem_table,
            start_time=self.start_time,
            end_time=self.end_time,
            device_id=MemTableTestUtils.device_id0,
            measurement_id=MemTableTestUtils.measurement_id0,
            data_type=MemTableTestUtils.data_type0
        )
        flush_task = MemTableFlushTask(self.mem_table, self.writer, self.storage_group)
        self.assertTrue(
            len(self.writer.get_visible_metadata_list(
                device_id=MemTableTestUtils.device_id0,
                measurement_id=MemTableTestUtils.measurement_id0,
                data_type=MemTableTestUtils.data_type0
            )) == 0
        )
        flush_task.sync_flush_mem_table()
        self.writer.make_metadata_visible()
        self.assertEqual(
            len(self.writer.get_visible_metadata_list(
                device_id=MemTableTestUtils.device_id0,
                measurement_id=MemTableTestUtils.measurement_id0,
                data_type=MemTableTestUtils.data_type0
            )), 1
        )
        chunk_meta_data = self.writer.get_visible_metadata_list(
            device_id=MemTableTestUtils.device_id0,
            measurement_id=MemTableTestUtils.measurement_id0,
            data_type=MemTableTestUtils.data_type0
        )[0]
        self.assertEqual(MemTableTestUtils.measurement_id0, chunk_meta_data.measurement_uid)
        self.assertEqual(self.start_time, chunk_meta_data.get_start_time())
        self.assertEqual(self.end_time, chunk_meta_data.get_end_time())
        self.assertEqual(MemTableTestUtils.data_type0, chunk_meta_data.get_data_type())
        self.assertEqual((self.end_time - self.start_time) + 1, chunk_meta_data.num_of_points)

    @unittest.skipIf(TestConstant.OUTPUT_DATA_DIR == "", "Test data directory does not exist")
    def test_flush_vector_mem_table(self):
        MemTableTestUtils.produce_vector_data(self.mem_table)
        flush_task = MemTableFlushTask(self.mem_table, self.writer, self.storage_group)
        self.assertTrue(
            len(self.writer.get_visible_metadata_list(
                device_id=MemTableTestUtils.device_id0,
                measurement_id="vectorName.sensor0",
                data_type=TSDataType.BOOLEAN
            )) == 0
        )
        flush_task.sync_flush_mem_table()
        self.writer.make_metadata_visible()
        self.assertEqual(len(self.writer.get_visible_metadata_list(
            device_id=MemTableTestUtils.device_id0,
            measurement_id="vectorName.sensor0",
            data_type=TSDataType.BOOLEAN
        )), 1)
        chunk_meta_data = self.writer.get_visible_metadata_list(
            device_id=MemTableTestUtils.device_id0,
            measurement_id="vectorName.sensor0",
            data_type=TSDataType.BOOLEAN
        )[0]
        self.assertEqual("vectorName.sensor0", chunk_meta_data.measurement_uid)
        self.assertEqual(self.start_time, chunk_meta_data.get_start_time())
        self.assertEqual(self.end_time, chunk_meta_data.get_end_time())
        self.assertEqual(TSDataType.BOOLEAN, chunk_meta_data.get_data_type())
        self.assertEqual((self.end_time - self.start_time) + 1, chunk_meta_data.num_of_points)

    @unittest.skipIf(TestConstant.OUTPUT_DATA_DIR == "", "Test data directory does not exist")
    def test_flush_nullable_vector_mem_table(self):
        MemTableTestUtils.produce_nullable_vector_data(self.mem_table)
        flush_task = MemTableFlushTask(self.mem_table, self.writer, self.storage_group)
        self.assertTrue(
            len(self.writer.get_visible_metadata_list(
                device_id=MemTableTestUtils.device_id0,
                measurement_id="vectorName.sensor0",
                data_type=TSDataType.BOOLEAN
            )) == 0
        )
        flush_task.sync_flush_mem_table()
        self.writer.make_metadata_visible()
        self.assertEqual(len(self.writer.get_visible_metadata_list(
            device_id=MemTableTestUtils.device_id0,
            measurement_id="vectorName.sensor0",
            data_type=TSDataType.BOOLEAN
        )), 1)
        chunk_meta_data = self.writer.get_visible_metadata_list(
            device_id=MemTableTestUtils.device_id0,
            measurement_id="vectorName.sensor0",
            data_type=TSDataType.BOOLEAN
        )[0]
        self.assertEqual("vectorName.sensor0", chunk_meta_data.measurement_uid)
        self.assertEqual(self.start_time, chunk_meta_data.get_start_time())
        self.assertEqual(self.end_time, chunk_meta_data.get_end_time())
        self.assertEqual(TSDataType.BOOLEAN, chunk_meta_data.get_data_type())
        self.assertEqual((self.end_time - self.start_time) + 1, chunk_meta_data.num_of_points)

if __name__ == "__main__":
    unittest.main()
