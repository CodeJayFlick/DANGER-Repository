import unittest
from abc import ABCMeta, abstractmethod


class RaftMemberTest(unittest.TestCase):
    def test_sync_leader_strong_consistency_check_false(self):
        # 1. write request : Strong consistency level with syncLeader false
        data_group_member_with_write_strong_consistency_false = self.new_data_group_member_with_sync_leader_false(0, False)
        cluster_descriptor.get_config().set_consistency_level("STRONG_CONSISTENCY")
        try:
            data_group_member_with_write_strong_consistency_false.wait_until_catch_up(RaftMember.StrongCheckConsistency())
        except CheckConsistencyException as e:
            self.assertIsNotNone(e)
            self.assertEqual(CheckConsistencyException.CHECK_STRONG_CONSISTENCY_EXCEPTION, e)

    def test_sync_leader_strong_consistency_check_true(self):
        # 1. write request : Strong consistency level with syncLeader false
        data_group_member_with_write_strong_consistency_true = self.new_data_group_member_with_sync_leader_true(0, False)
        cluster_descriptor.get_config().set_consistency_level("STRONG_CONSISTENCY")
        try:
            partitioned_snapshot_log_manager = mock(PartitionedSnapshotLogManager())
            when(partitioned_snapshot_log_manager).get_max_have_applied_commit_index().thenReturn(1000L)
            data_group_member_with_write_strong_consistency_true.set_log_manager(partitioned_snapshot_log_manager)

            data_group_member_with_write_strong_consistency_true.wait_until_catch_up(RaftMember.StrongCheckConsistency())
        except CheckConsistencyException:
            self.fail()

    def test_sync_leader_mid_consistency_check_false(self):
        # 1. write request : Strong consistency level with syncLeader false
        data_group_member_with_write_strong_consistency_false = self.new_data_group_member_with_sync_leader_false(0, False)
        cluster_descriptor.get_config().set_consistency_level("MID_CONSISTENCY")
        cluster_descriptor.get_config().set_max_read_log_lag(1)
        try:
            partitioned_snapshot_log_manager = mock(PartitionedSnapshotLogManager())
            when(partitioned_snapshot_log_manager).get_max_have_applied_commit_index().thenReturn(-2L)
            data_group_member_with_write_strong_consistency_false.set_log_manager(partitioned_snapshot_log_manager)

            data_group_member_with_write_strong_consistency_false.wait_until_catch_up(RaftMember.MidCheckConsistency())
        except CheckConsistencyException as e:
            self.assertEqual(CheckConsistencyException.CHECK_MID_CONSISTENCY_EXCEPTION, e)

    def test_sync_leader_mid_consistency_check_true(self):
        # 1. write request : Strong consistency level with syncLeader false
        data_group_member_with_write_strong_consistency_true = self.new_data_group_member_with_sync_leader_true(0, False)
        cluster_descriptor.get_config().set_consistency_level("MID_CONSISTENCY")
        cluster_descriptor.get_config().set_max_read_log_lag(500)
        try:
            partitioned_snapshot_log_manager = mock(PartitionedSnapshotLogManager())
            when(partitioned_snapshot_log_manager).get_max_have_applied_commit_index().thenReturn(600L)
            data_group_member_with_write_strong_consistency_true.set_log_manager(partitioned_snapshot_log_manager)

            data_group_member_with_write_strong_consistency_true.wait_until_catch_up(RaftMember.MidCheckConsistency())
        except CheckConsistencyException:
            self.fail()

    def test_sync_leader_weak_consistency_check_false(self):
        # 1. write request : Strong consistency level with syncLeader false
        data_group_member_with_write_strong_consistency_false = self.new_data_group_member_with_sync_leader_false(0, False)
        cluster_descriptor.get_config().set_consistency_level("WEAK_CONSISTENCY")
        cluster_descriptor.get_config().set_max_read_log_lag(1)
        try:
            partitioned_snapshot_log_manager = mock(PartitionedSnapshotLogManager())
            when(partitioned_snapshot_log_manager).get_max_have_applied_commit_index().thenReturn(-2L)
            data_group_member_with_write_strong_consistency_false.set_log_manager(partitioned_snapshot_log_manager)

            data_group_member_with_write_strong_consistency_false.wait_until_catch_up(None)
        except CheckConsistencyException:
            self.fail()

    def test_sync_leader_weak_consistency_check_true(self):
        # 1. write request : Strong consistency level with syncLeader false
        data_group_member_with_write_strong_consistency_true = self.new_data_group_member_with_sync_leader_true(0, False)
        cluster_descriptor.get_config().set_consistency_level("WEAK_CONSISTENCY")
        cluster_descriptor.get_config().set_max_read_log_lag(500)
        try:
            partitioned_snapshot_log_manager = mock(PartitionedSnapshotLogManager())
            when(partitioned_snapshot_log_manager).get_max_have_applied_commit_index().thenReturn(600L)
            data_group_member_with_write_strong_consistency_true.set_log_manager(partitioned_snapshot_log_manager)

            data_group_member_with_write_strong_consistency_true.wait_until_catch_up(None)
        except CheckConsistencyException:
            self.fail()

    def new_data_group_member_with_sync_leader_false(self, node, sync_leader):
        return TestDataGroupMember(node, partition_table.get_header_group(RaftNode(node, 0)))({
            'sync_leader': lambda check_consistency: sync_leader,
            'request_commit_id_async': lambda: RequestCommitIndexResponse(5, 5, 5),
            'append_entry': lambda request: Response.AGREE,
            'get_async_client': lambda node: TestAsyncDataClient(node, data_group_member_map)
        })

    def new_data_group_member_with_sync_leader_true(self, node, sync_leader):
        return TestDataGroupMember(node, partition_table.get_header_group(RaftNode(node, 0)))({
            'sync_leader': lambda check_consistency: sync_leader,
            'request_commit_id_async': lambda: RequestCommitIndexResponse(1000, 1000, 1000),
            'append_entry': lambda request: Response.AGREE,
            'get_async_client': lambda node: TestAsyncDataClient(node, data_group_member_map)
        })


class TestDataGroupMember:
    def __init__(self, node, meta_group):
        self.this_node = node
        self.meta_group_member = meta_group
        self.leader = node
        self.character = NodeCharacter.LEADER
        self.log_manager = TestPartitionedLogManager()
        self.append_log_thread_pool = test_thread_pool

    def sync_leader(self, check_consistency):
        return True

    def request_commit_id_async(self):
        return RequestCommitIndexResponse(5, 5, 5)

    def append_entry(self, request):
        return Response.AGREE

    def get_async_client(self, node):
        try:
            return TestAsyncDataClient(node, data_group_member_map)
        except IOException as e:
            return None


class NodeCharacter(metaclass=ABCMeta):
    LEADER = 'LEADER'


if __name__ == '__main__':
    unittest.main()
