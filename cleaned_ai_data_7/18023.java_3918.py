import os
from unittest import TestCase
from iotdb.tsfile.file.metadata.enums import TSDataType


class TestWriteLogNodeManager(TestCase):

    def setUp(self):
        self.config = IoTDBConfig()
        self.enable_wal = self.config.is_enable_wal()
        self.config.set_enable_wal(True)
        EnvironmentUtils.env_set_up()

    def tearDown(self):
        EnvironmentUtils.clean_env()
        self.config.set_enable_wal(self.enable_wal)

    def test_get_and_delete(self):

        identifier = "testLogNode"
        manager = MultiFileLogNodeManager().get_instance()
        log_node = manager.get_node(identifier, lambda: [ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2), ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2)])
        self.assertEqual(identifier, log_node.identifier)

        same_node = manager.get_node(identifier, lambda: [ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2), ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2)])
        self.assertIs(log_node, same_node)

        manager.delete_node(identifier, lambda buffers: [buffer for buffer in buffers])
        not_same_node = manager.get_node(identifier, lambda: [ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2), ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2)])
        self.assertNotIsInstance(log_node, not_same_node)
        manager.delete_node(identifier, lambda buffers: [buffer for buffer in buffers])

    def test_auto_sync(self):

        flush_wal_period = config.get_flush_wal_threshold()
        config.set_force_wal_period_in_ms(10000)

        temp_restore = os.path.join(os.getcwd(), "managerTest", "restore")
        temp_processor_store = os.path.join(os.getcwd(), "managerTest", "processorStore")

        manager = MultiFileLogNodeManager().get_instance()
        log_node = manager.get_node("root.managerTest", lambda: [ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2), ByteBuffer.allocate_direct(IoTDBConfig().wal_buffer_size() // 2)])

        bw_insert_plan = InsertRowPlan(PartialPath("logTestDevice"), 100, ["s1", "s2", "s3", "s4"], [TSDataType.DOUBLE, TSDataType.INT64, TSDataType.TEXT, TSDataType.BOOLEAN], ["1.0", "15", "str", "false"])
        delete_plan = DeletePlan(Long.MIN_VALUE, 50, PartialPath("root.logTestDevice.s1"))

        wal_file_path = os.path.join(log_node.get_log_directory(), "wal1")
        self.assertFalse(os.path.exists(wal_file_path))

        log_node.write(bw_insert_plan)
        log_node.write(delete_plan)

        time.sleep(config.get_force_wal_period_in_ms() + 1000)
        self.assertTrue(os.path.exists(wal_file_path))

        buffers = log_node.delete()
        for buffer in buffers:
            MmapUtil.clean(MappedByteBuffer(buffer))
        config.set_force_wal_period_in_ms(flush_wal_period)

        os.remove(temp_restore)
        os.remove(temp_processor_store)
        os.rmdir(os.path.dirname(temp_restore))


if __name__ == "__main__":
    unittest.main()
