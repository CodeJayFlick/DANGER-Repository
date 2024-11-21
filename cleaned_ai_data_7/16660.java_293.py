import unittest
from abc import ABCMeta, abstractmethod


class MetaLogApplierTest(unittest.TestCase):

    def setUp(self):
        self.nodes = set()
        self.test_meta_group_member = TestMetaGroupMember()

    def tearDown(self):
        self.test_meta_group_member.stop()
        self.test_meta_group_member.close_log_manager()
        super().tearDown()

    def test_apply_add_node(self):
        self.nodes.clear()
        self.test_meta_group_member.set_coordinator(Coordinator())
        self.test_meta_group_member.set_partition_table(TestUtils.get_partition_table(3))
        node = Node("localhost", 1111, 0, 2222, Constants.RPC_PORT, "localhost")
        log = AddNodeLog()
        log.new_node = node
        log.partition_table = TestUtils.serialize_partition_table
        self.test_meta_group_member.apply(log)
        self.assertTrue(node in self.nodes)

    def test_apply_remove_node(self):
        self.nodes.clear()

        node = self.test_meta_group_manager.get_this_node()
        log = RemoveNodeLog()
        log.partition_table = TestUtils.serialize_partition_table
        log.removed_node = node
        self.test_meta_group_member.apply(log)
        self.assertFalse(node in self.nodes)

    def test_apply_metadata_creation(self):
        physical_plan_log = PhysicalPlanLog()
        set_storage_group_plan = SetStorageGroupPlan(PartialPath("root.applyMeta"))
        physical_plan_log.plan = set_storage_group_plan

        self.test_meta_group_manager.apply(physical_plan_log)
        self.assertTrue(IoTDB.meta_manager.is_path_exist(PartialPath("root.applyMeta")))

        create_time_series_plan = CreateTimeSeriesPlan(
            PartialPath("root.applyMeta.s1"),
            TSDataType.DOUBLE,
            TSEncoding.RLE,
            CompressionType.SNAPPY,
            {},
            {},
            {}
        )
        physical_plan_log.plan = create_time_series_plan
        self.test_meta_group_manager.apply(physical_plan_log)
        self.assertTrue(IoTDB.meta_manager.is_path_exist(PartialPath("root.applyMeta.s1")))
        self.assertEqual(
            TSDataType.DOUBLE, 
            IoTDB.meta_manager.get_series_type(PartialPath("root.applyMeta.s1"))
        )

    def test_apply_create_snapshot(self):
        create_snapshot_plan = CreateSnapshotPlan()
        physical_plan_log = PhysicalPlanLog(create_snapshot_plan)
        self.test_meta_group_member.apply(physical_plan_log)
        self.assertIsNone(physical_plan_log.exception)


if __name__ == '__main__':
    unittest.main()
