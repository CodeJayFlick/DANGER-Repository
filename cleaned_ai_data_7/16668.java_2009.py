import unittest
from io import BytesIO
from typing import Any

class LogParserTest(unittest.TestCase):

    def setUp(self):
        self.log_parser = None  # Initialize log parser instance here if needed.

    @unittest.skipIf(sys.version_info < (3,8), "This test requires Python 3.8 or higher.")
    def test_add_node_log(self) -> None:
        from iotdb.cluster.log import AddNodeLog
        from iotdb.utils.test_utils import TestUtils

        log = AddNodeLog()
        log.new_node = TestUtils.get_test_node(5)
        log.partition_table = TestUtils.serialize_partition_table
        log.curr_log_index = 8
        log.curr_log_term = 8

        buffer = BytesIO(log.serialize().encode())
        serialized = self.log_parser.parse(buffer.getvalue())

        self.assertEqual(log, serialized)

    @unittest.skipIf(sys.version_info < (3,8), "This test requires Python 3.8 or higher.")
    def test_physical_plan_log(self) -> None:
        from iotdb.cluster.log import PhysicalPlanLog
        from iotdb.db.query.plan import SetStorageGroupPlan
        from iotdb.utils.test_utils import TestUtils

        log = PhysicalPlanLog()
        set_storage_group_plan = SetStorageGroupPlan(PartialPath(TestUtils.get_test_sg(5)))
        log.set_plan(set_storage_group_plan)
        log.curr_log_index = 8
        log.curr_log_term = 8

        buffer = BytesIO(log.serialize().encode())
        serialized = self.log_parser.parse(buffer.getvalue())

        self.assertEqual(log, serialized)

    @unittest.skipIf(sys.version_info < (3,8), "This test requires Python 3.8 or higher.")
    def test_close_file_log(self) -> None:
        from iotdb.cluster.log import CloseFileLog
        from iotdb.utils.test_utils import TestUtils

        log = CloseFileLog(TestUtils.get_test_sg(5), 0, False)
        log.curr_log_index = 8
        log.curr_log_term = 8

        buffer = BytesIO(log.serialize().encode())
        serialized = self.log_parser.parse(buffer.getvalue())

        self.assertEqual(log, serialized)

    @unittest.skipIf(sys.version_info < (3,8), "This test requires Python 3.8 or higher.")
    def test_remove_node_log(self) -> None:
        from iotdb.cluster.log import RemoveNodeLog
        from iotdb.utils.test_utils import TestUtils

        log = RemoveNodeLog()
        log.partition_table = TestUtils.serialize_partition_table
        log.removed_node = TestUtils.get_test_node(0)
        log.curr_log_index = 8
        log.curr_log_term = 8

        buffer = BytesIO(log.serialize().encode())
        serialized = self.log_parser.parse(buffer.getvalue())

        self.assertEqual(log, serialized)

    @unittest.skipIf(sys.version_info < (3,8), "This test requires Python 3.8 or higher.")
    def test_empty_content_log(self) -> None:
        from iotdb.cluster.log import EmptyContentLog

        log = EmptyContentLog()
        log.curr_log_index = 8
        log.curr_log_term = 8

        buffer = BytesIO(log.serialize().encode())
        serialized = self.log_parser.parse(buffer.getvalue())

        self.assertEqual(log, serialized)

    @unittest.skipIf(sys.version_info < (3,8), "This test requires Python 3.8 or higher.")
    def test_log_plan(self) -> None:
        from iotdb.cluster.log import AddNodeLog
        from iotdb.db.query.plan import LogPlan

        log = AddNodeLog(TestUtils.serialize_partition_table, TestUtils.get_test_node(0))
        log.meta_log_index = 1

        try:
            plan = LogPlan(log.serialize().encode())
            buffer = BytesIO(plan.encode())
            PhysicalPlan.deserialize(buffer.getvalue())

            self.log_parser.parse(plan.get_log())
        except (IllegalPathException, IOException, UnknownLogTypeException):
            self.fail()

if __name__ == '__main__':
    unittest.main()
