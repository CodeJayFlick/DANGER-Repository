import unittest
from io import File
import time
import threading

class SlotManagerTest(unittest.TestCase):

    def setUp(self):
        self.prev_enable_log_persistence = ClusterDescriptor.getInstance().getConfig().isEnableRaftLogPersistence()
        self.prev_replica_num = ClusterDescriptor.getInstance().getConfig().getReplicationNum()
        ClusterDescriptor.getInstance().getConfig().setEnableRaftLogPersistence(True)
        ClusterDescriptor.getInstance().getConfig().setReplicationNum(2)

    def test_wait_slot(self):
        slot_manager.wait_slot(0)
        slot_manager.set_to_pulling(0, None)
        thread = threading.Thread(target=lambda: time.sleep(200) and slot_manager.set_to_null(0))
        thread.start()
        slot_manager.wait_slot(0)
        ClusterDescriptor.getInstance().getConfig().setEnableRaftLogPersistence(self.prev_enable_log_persistence)
        ClusterDescriptor.getInstance().getConfig().setReplicationNum(self.prev_replica_num)

    def test_wait_slot_for_write(self):
        slot_manager.wait_slot(0)
        slot_manager.set_to_pulling_writable(0)
        slot_manager.wait_slot_for_write(0)
        slot_manager.set_to_pulling(0, None)
        thread = threading.Thread(target=lambda: time.sleep(200) and slot_manager.set_to_null(0))
        thread.start()
        slot_manager.wait_slot_for_write(0)

    def test_get_status(self):
        self.assertEqual(slot_manager.get_status(0), NULL)
        slot_manager.set_to_pulling_writable(0)
        self.assertEqual(slot_manager.get_status(0), PULLING_WRITABLE)
        slot_manager.set_to_pulling(0, None)
        self.assertEqual(slot_manager.get_status(0), PULLING)
        slot_manager.set_to_null(0)
        self.assertEqual(slot_manager.get_status(0), NULL)

    def test_get_source(self):
        self.assertIsNone(slot_manager.get_source(0))
        source = Node()
        slot_manager.set_to_pulling(0, source)
        self.assertEqual(source, slot_manager.get_source(0))
        slot_manager.set_to_pulling_writable(0)
        self.assertEqual(source, slot_manager.get_source(0))
        slot_manager.set_to_null(0)
        self.assertIsNone(slot_manager.get_source(0))

    def test_serialize(self):
        dummy_member_dir = File("test")
        try:
            slot_manager = SlotManager(5, str(dummy_member_dir), "")
            slot_manager.set_to_null(0)
            slot_manager.set_to_pulling(1, TestUtils.getNode(1))
            slot_manager.set_to_pulling(2, TestUtils.getNode(2))
            slot_manager.set_to_pulling_writable(2)
            slot_manager.set_to_sending(3)
            slot_manager.sent_one_replication(3)
            slot_manager.set_to_sending(4)
            for i in range(ClusterDescriptor.getInstance().getConfig().getReplicationNum()):
                slot_manager.sent_one_replication(4)

            recovered_slot_manager = SlotManager(5, str(dummy_member_dir), "")
            self.assertEqual(recovered_slot_manager.get_status(0), NULL)
            self.assertEqual(recovered_slot_manager.get_status(1), PULLING)
            self.assertEqual(recovered_slot_manager.get_status(2), PULLING_WRITABLE)
            self.assertEqual(recovered_slot_manager.get_status(3), SENDING)
            self.assertEqual(recovered_slot_manager.get_status(4), SENT)

        finally:
            EnvironmentUtils.clean_dir(str(dummy_member_dir))

    def test_deserialize(self):
        pass

if __name__ == '__main__':
    unittest.main()
