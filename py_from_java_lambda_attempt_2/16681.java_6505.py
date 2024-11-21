Here is the translation of the Java code into Python:

```Python
import logging
from thrift import TException
from thrift.protocol import TBinaryProtocol
from thrift.transport import TTransport
from thrift.async import AsyncMethodCallback
from iotdb.tsfile.exception.write import WriteProcessException
from iotdb.tsfile.write.schema import TimeseriesSchema

class PullSnapshotTaskTest:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.source_member = None
        self.target_member = None
        self.timeseries_schemas = []
        self.ts_file_resources = []
        self.hint_registered = False
        self.required_retries = 0

    @classmethod
    def setUpClass(cls):
        cls.default_compaction_thread = IoTDBDescriptor.getInstance().getConfig().getConcurrentCompactionThread()

    def setUp(self):
        IoTDBDescriptor.getInstance().getConfig().setConcurrentCompactionThread(0)
        super().setUp()
        self.hint_registered = False
        self.source_member = TestDataGroupMember()
        self.target_member = TestDataGroupMember()
        self.timeseries_schemas = []
        self.required_retries = 0

    def test_async(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(True)
        try:
            self.test_normal(False)
        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_read_only(self):
        self.test_normal(True)
        self.assertTrue(self.target_member.is_read_only())

    def test_sync(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(False)
        try:
            self.test_normal(False)
        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_with_retry(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        pull_snapshot_retry_interval_ms = ClusterDescriptor.getInstance().getConfig().getPullSnapshotRetryIntervalMs()
        ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(False)
        ClusterDescriptor.getInstance().getConfig().setPullSnapshotRetryIntervalMs(100)
        try:
            self.required_retries = 3
            self.test_normal(False)
        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)
            ClusterDescriptor.getInstance().getConfig().setPullSnapshotRetryIntervalMs(pull_snapshot_retry_interval_ms)

    def test_normal(self, requires_read_only):
        partition_group = PartitionGroup()
        slots = []
        for i in range(20):
            slots.append(i)
            self.source_member.get_slot_manager().set_to_pulling(i, TestUtils.getNode(1))
        descriptor = PullSnapshotTaskDescriptor(partition_group, slots, requires_read_only)

        task = PullSnapshotTask(descriptor, self.source_member, FileSnapshot.Factory.INSTANCE, None)
        task.call()

        for timeseries_schema in self.timeseries_schemas:
            self.assertTrue(IoTDB.meta_manager.is_path_exist(PartialPath(timeseries_schema.get_full_path())))

    def tearDown(self):
        if hasattr(self, 'source_member'):
            self.source_member.close_log_manager()
        if hasattr(self, 'target_member'):
            self.target_member.close_log_manager()
        if hasattr(self, 'source_member'):
            self.source_member.stop()
        if hasattr(self, 'target_member'):
            self.target_member.stop()
        super().tearDown()
        IoTDBDescriptor.getInstance().getConfig().setConcurrentCompactionThread(self.default_compaction_thread)

class TestDataGroupMember:
    def get_async_client(self, node):
        return TestAsyncDataClient(node, None)

    def get_sync_client(self, node):
        return SyncDataClient(None)

    def register_pull_snapshot_hint(self, descriptor):
        self.hint_registered = True

class PullSnapshotTaskDescriptor:
    pass

class PartitionGroup:
    pass

class FileSnapshotFactory:
    INSTANCE = None
```

Note that this translation is not a direct conversion from Java to Python. It's more like an interpretation of the code in terms of Python syntax and semantics.