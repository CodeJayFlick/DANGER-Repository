import unittest
from thrift import TException
from thrift.protocol.TBinaryProtocol import TBinaryProtocolFactory
from iotdb.tsfile.file.metadata.enums import TSDataType


class TestMetaGroupMember:
    def set_client_provider(self, client_provider):
        self.client_provider = client_provider

    def get_async_data_client(self, node, timeout):
        return AsyncDataClient(None, None, node, None)


class AsyncDataClient:
    def __init__(self, *args):
        pass

    def query_single_series(self, request, result_handler):
        raise TException("Don't worry, this is the exception I constructed.")


class PartitionGroup:
    def add(self, node):
        self.nodes = [node]


class DataSourceInfo:
    def __init__(self, group, data_type, request, context, meta_group_member, query_context=None):
        self.group = group
        self.data_type = data_type
        self.request = request
        self.context = context if query_context is None else query_context
        self.meta_group_member = meta_group_member

    def has_next_data_client(self, has_more, min_value):
        return False


class DatasourceInfoTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.meta_group_member = TestMetaGroupMember()
        cls.meta_group_member.set_client_provider(TBinaryProtocolFactory())

    def test_failed_all(self):
        group = PartitionGroup()
        node0, node1, node2 = [None] * 3
        for i in range(3):
            group.add(node[i])

        request = None
        context = "context"

        try:
            source_info = DataSourceInfo(group, TSDataType.DOUBLE, request, context, self.meta_group_member)
            has_client = source_info.has_next_data_client(False, 0)

            self.assertFalse(has_client)
        finally:
            pass


if __name__ == '__main__':
    unittest.main()
