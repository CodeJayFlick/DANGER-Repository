import unittest
from typing import Dict, List

class SerializeLogTest(unittest.TestCase):

    def test_physical_plan_log(self):
        from iotdb_cluster.log.logtypes import PhysicalPlanLog
        log = PhysicalPlanLog()
        log.curr_log_index = 2
        log.curr_log_term = 2
        plan = InsertRowPlan()
        plan.prefix_path = PartialPath("root.d1")
        plan.measurements = ["s1", "s2", "s3"]
        plan.need_infer_type = True
        data_types = [TSDataType.DOUBLE, TSDataType.INT32, TSDataType.TEXT]
        values = ["0.1", 1, "\"dd\""]
        schemas = [
            TestUtils.get_test_measurement_m_node(1),
            TestUtils.get_test_measurement_m_node(2),
            TestUtils.get_test_measurement_m_node(3)
        ]
        for schema in schemas:
            schema.schema.type = TSDataType.DOUBLE
        plan.measurement_m_nodes = schemas
        plan.time = 1
        log.plan = plan

        byte_buffer = log.serialize()
        log_prime = LogParser().parse(byte_buffer)
        self.assertEqual(log, log_prime)

    def test_add_node_log(self):
        from iotdb_cluster.log.logtypes import AddNodeLog
        log = AddNodeLog()
        log.partition_table = TestUtils.seralize_partition_table
        log.curr_log_index = 2
        log.curr_log_term = 2
        new_node = Node("apache.iotdb.com", 1234, 1, 4321, Constants.RPC_PORT, "apache.iotdb.com")
        log.new_node = new_node

        byte_buffer = log.serialize()
        log_prime = LogParser().parse(byte_buffer)
        self.assertEqual(log, log_prime)

    def test_close_file_log(self):
        from iotdb_cluster.log.logtypes import CloseFileLog
        log = CloseFileLog("root.sg1", 0, True)
        log.curr_log_index = 2
        log.curr_log_term = 2

        byte_buffer = log.serialize()
        log_prime = LogParser().parse(byte_buffer)
        self.assertTrue(log_prime.is_seq())
        self.assertEqual("root.sg1", log_prime.get_storage_group_name())
        self.assertEqual(log, log_prime)

    def test_remove_node_log(self):
        from iotdb_cluster.log.logtypes import RemoveNodeLog
        log = RemoveNodeLog()
        log.partition_table = TestUtils.seralize_partition_table
        log.curr_log_index = 2
        log.curr_log_term = 2
        removed_node = TestUtils.get_node(0)
        log.removed_node = removed_node

        byte_buffer = log.serialize()
        log_prime = LogParser().parse(byte_buffer)
        self.assertEqual(log, log_prime)

    def test_empty_content_log(self):
        from iotdb_cluster.log.logtypes import EmptyContentLog
        log = EmptyContentLog(2, 2)
        byte_buffer = log.serialize()

        log_prime = LogParser().parse(byte_buffer)
        self.assertEqual(log, log_prime)


if __name__ == '__main__':
    unittest.main()
