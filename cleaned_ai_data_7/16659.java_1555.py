import logging
from thrift import Thrift
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol
from thrift.server import TFramedTransport
from thrift.Thrift import ThriftException
from thrift.protocol import TCompactProtocol
from thrift.protocol import TJSONProtocol

class DataLogApplierTest:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.partial_write_enabled = False
        self.is_partition_enabled = True
        self.test_meta_group_member = TestMetaGroupMember()
        self.test_data_group_member = TestDataGroupMember()

    @staticmethod
    def get_logger():
        return logging.getLogger(__name__)

    def setUp(self):
        IoTDB.set_meta_manager(CMManager.getInstance())
        test_meta_group_member.set_coordinator(Coordinator())
        MetaPuller.getInstance().init(test_meta_group_member)
        super().setUp()
        meta_puller = MetaPuller.getInstance()
        all_nodes = PartitionGroup()
        for i in range(0, 100, 10):
            all_nodes.add(TestUtils.get_test_node(i))
        test_meta_group_member.set_all_nodes(all_nodes)
        test_meta_group_member.set_partition_table(SlotPartitionTable(all_nodes, TestUtils.get_test_node(0)))
        test_meta_group_member.set_this_node(TestUtils.get_test_node(0))

    def tearDown(self):
        test_data_group_member.stop()
        test_data_group_member.close_log_manager()
        test_meta_group_member.stop()
        test_meta_group_member.close_log_manager()
        super().tearDown()

class TestMetaGroupMember:
    pass

class TestDataGroupMember:
    pass
