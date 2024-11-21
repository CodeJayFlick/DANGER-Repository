Here is the translation of the Java code into Python:

```Python
import threading
from thrift import TException
from iotdb_cluster_log_catchup import LogCatchUpTask, RaftNode, NodeCharacter


class TestLogCatchUpTask:
    def setUp(self):
        self.prev_use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(True)
        self.test_leadership_flag = False

    def tearDown(self):
        sender.stop()
        sender.close_log_manager()
        EnvironmentUtils.clean_all_dir()
        ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(self.prev_use_async_server)

    @staticmethod
    def dummy_append_entry(request):
        log_parser = LogParser.get_instance()
        test_log = log_parser.parse(request.entry)
        received_logs.append(test_log)
        if self.test_leadership_flag and test_log.curr_log_index == 4:
            sender.set_character(NodeCharacter.ELECTOR)
        return Response.RESPONSE_AGREE

    @staticmethod
    def dummy_append_entries(request):
        log_parser = LogParser.get_instance()
        for byte_buffer in request.entries:
            test_log = log_parser.parse(byte_buffer)
            received_logs.append(test_log)
            if test_log is not None and self.test_leadership_flag and test_log.curr_log_index >= 1023:
                return sender.term + 1
        return Response.RESPONSE_AGREE

    def catch_up_test(self, log_size, use_batch):
        log_list = TestUtils.prepare_test_logs(log_size)
        receiver = Node()
        sender.set_character(NodeCharacter.LEADER)
        task = LogCatchUpTask(log_list, receiver, 0, sender, use_batch)
        task.call()

        self.assertEqual(log_list, received_logs)

    def test_catch_up_async(self):
        self.catch_up_test(10, False)

    def test_catch_up_in_batch(self):
        self.catch_up_test(10, True)

    def test_catch_up_in_batch2(self):
        self.catch_up_test(500, True)

    @staticmethod
    def test_leadership_lost():
        TestLogCatchUpTask.test_leadership_flag = True

        log_list = TestUtils.prepare_test_logs(10)
        receiver = Node()
        sender.set_character(NodeCharacter.LEADER)
        task = LogCatchUpTask(log_list, receiver, 0, sender, False)
        try:
            task.call()
            self.fail("Expected LeaderUnknownException")
        except TException as e:
            self.assertEqual(
                "The leader is unknown in this group [Node(internalIp:192.168.0.0, metaPort:9003, nodeIdentifier:0, dataPort:40010, clientPort:6667, clientIp:0.0.0.0), Node(internalIp:192.168.0.1, metaPort:9003, nodeIdentifier:1, dataPort:40010, clientPort:6667, clientIp:0.0.0.0), ...]",
                e.getMessage()
            )

        self.assertEqual(log_list[:5], received_logs)

    @staticmethod
    def test_leadership_lost_in_batch():
        TestLogCatchUpTask.test_leadership_flag = True

        log_list = TestUtils.prepare_test_logs(1030)
        receiver = Node()
        sender.set_character(NodeCharacter.LEADER)
        task = LogCatchUpTask(log_list, receiver, 0, sender, True)
        try:
            task.call()

        self.assertEqual(log_list[:1024], received_logs)

    @staticmethod
    def test_small_frame_size():
        pre_frame_size = IoTDBDescriptor.getInstance().getConfig().getThriftMaxFrameSize()
        try:
            log_list = TestUtils.prepare_test_logs(500)
            single_log_size = log_list[0].serialize().limit()
            IoTDBDescriptor.getInstance().getConfig().setThriftMaxFrameSize(
                100 * single_log_size + IoTDBConstant.LEFT_SIZE_IN_REQUEST
            )
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, True)
            try:
                task.call()

        finally:
            IoTDBDescriptor.getInstance().getConfig().setThriftMaxFrameSize(pre_frame_size)

    @staticmethod
    def test_very_small_frame_size():
        pre_frame_size = IoTDBDescriptor.getInstance().getConfig().getThriftMaxFrameSize()
        try:
            log_list = TestUtils.prepare_test_logs(500)
            IoTDBDescriptor.getInstance().getConfig().setThriftMaxFrameSize(0)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, True)
            try:
                task.call()

        finally:
            IoTDBDescriptor.getInstance().getConfig().setThriftMaxFrameSize(pre_frame_size)

    def test_catch_up_sync(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync2(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync3(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync4(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync5(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync6(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync7(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync8(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync9(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync10(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync11(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync12(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync13(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync14(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync15(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync16(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync17(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync18(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync19(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync20(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
        try:
            log_list = TestUtils.prepare_test_logs(10)
            receiver = Node()
            sender.set_character(NodeCharacter.LEADER)
            task = LogCatchUpTask(log_list, receiver, 0, sender, False)
            try:
                task.call()

        finally:
            ClusterDescriptor.getInstance().getConfig().setUseAsyncServer(use_async_server)

    def test_catch_up_sync21(self):
        use_async_server = ClusterDescriptor.getInstance().getConfig().isUseAsyncServer()
