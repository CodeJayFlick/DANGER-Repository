Here is the translation of the Java code to Python:
```
import logging

class CatchUpTaskTest:

    def __init__(self):
        self.received_logs = []
        self.leader_commit = 0
        self.header = None
        self.prev_use_async_server = False

    @property
    def received_logs(self):
        return self._received_logs

    @received_logs.setter
    def received_logs(self, value):
        self._received_logs = value

    @property
    def leader_commit(self):
        return self._leader_commit

    @leader_commit.setter
    def leader_commit(self, value):
        self._leader_commit = value

    @property
    def header(self):
        return self._header

    @header.setter
    def header(self, value):
        self._header = value

    def dummy_append_entry(self, request):
        log = self.received_logs[-1]
        test_log = None
        try:
            test_log = LogParser.get_instance().parse(request.entry)
        except Exception as e:
            return Response.RESPONSE_NULL
        if test_log.curr_log_index == log.curr_log_index + 1:
            self.leader_commit = max(request.leader_commit, self.leader_commit)
            self.received_logs.append(test_log)
            return Response.RESPONSE_AGREE
        elif test_log.curr_log_index == log.curr_log_index:
            self.leader_commit = max(request.leader_commit, self.leader_commit)
            return Response.RESPONSE_AGREE
        else:
            return Response.RESPONSE_LOG_MISMATCH

    def dummy_append_entries(self, request):
        for byte_buffer in request.entries:
            test_log = None
            try:
                test_log = LogParser.get_instance().parse(byte_buffer)
            except Exception as e:
                return Response.RESPONSE_NULL
            self.received_logs.append(test_log)
        self.leader_commit = max(request.leader_commit, self.leader_commit)
        return Response.RESPONSE_AGREE

    def dummy_match_term(self, index, term):
        if not self.received_logs:
            return True
        for received_log in self.received_logs:
            if received_log.curr_log_term == term and received_log.curr_log_index == index:
                return True
        return False

    @classmethod
    def setUp(cls):
        IoTDB.meta_manager.init()
        cls.prev_use_async_server = ClusterDescriptor.get_instance().get_config().is_use_async_server()
        ClusterDescriptor.get_instance().get_config().set_use_async_server(True)
        cls.received_logs = []

    @classmethod
    def tearDown(cls):
        IoTDB.meta_manager.clear()
        sender.stop()
        sender.close_log_manager()
        EnvironmentUtils.clean_all_dir()
        ClusterDescriptor.get_instance().get_config().set_use_async_server(cls.prev_use_async_server)

    @staticmethod
    def test_catch_up_empty():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)
            if i < 6:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0
        task = CatchUpTask(receiver, 0, peer, sender, 5)
        task.run()
        assert received_logs == log_list[1:]
        assert leader_commit == 9

    @staticmethod
    def test_partial_catch_up_async():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)
            if i < 6:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0
        task = CatchUpTask(receiver, 0, peer, sender, 5)
        task.run()
        assert received_logs == log_list[1:]
        assert leader_commit == 9

    @staticmethod
    def test_partial_catch_up_sync():
        use_async_server = ClusterDescriptor.get_instance().get_config().is_use_async_server()
        try:
            # 1. case 1: the matched index is in the middle of the logs interval
            log_list = []
            for i in range(10):
                log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
                log_list.append(log)
                if i < 6:
                    received_logs.append(log)
            sender.log_manager.append(log_list)
            sender.log_manager.commit_to(9)
            sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
            receiver = Node()
            sender.character = NodeCharacter.LEADER
            peer = Peer(10)
            peer.match_index = 0
            task = CatchUpTask(receiver, 0, peer, sender, 5)
            task.run()
            assert received_logs == log_list[1:]
            assert leader_commit == 9

        finally:
            ClusterDescriptor.get_instance().get_config().set_use_async_server(use_async_server)

    @staticmethod
    def test_catch_up_single():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0
        task = CatchUpTask(receiver, 0, peer, sender, 5)
        task.run()
        assert received_logs == log_list[1:]
        assert leader_commit == 9

    @staticmethod
    def test_catch_up_batch():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0
        task = CatchUpTask(receiver, 0, peer, sender, 5)
        task.run()
        assert received_logs == log_list[1:]
        assert leader_commit == 9

    @staticmethod
    def test_find_last_match_index():
        last_matched_index = 6
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)
        result_match_index = task.find_last_match_index(log_list)

        assert last_matched_index == result_match_index

    @staticmethod
    def test_find_last_match_index_case2():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case3():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case4():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case5():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case6():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case7():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case8():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case9():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case10():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log_list)
        sender.log_manager.commit_to(9)
        sender.log_manager.set_max_have_applied_commit_index(sender.log_manager.get_commit_log_index())
        receiver = Node()
        sender.character = NodeCharacter.LEADER
        peer = Peer(10)
        peer.match_index = 0

        task = CatchUpTask(receiver, 0, peer, sender, 5)

    @staticmethod
    def test_find_last_match_index_case11():
        log_list = []
        for i in range(10):
            log = EmptyContentLog(curr_log_index=i, curr_log_term=i)
            log_list.append(log)

            if i < last_matched_index:
                received_logs.append(log)
        sender.log_manager.append(log