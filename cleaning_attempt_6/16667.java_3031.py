import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set

class LogDispatcher:
    def __init__(self):
        self.appended_entries = {}
        self.down_node = set()

    def offer(self, request: 'SendLogRequest') -> None:
        # TO DO: implement the logic to handle SendLogRequest here
        pass

    def close(self) -> None:
        # TO DO: implement the logic to close LogDispatcher here
        pass


class Node:
    def __init__(self):
        self.id = 0

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value: int) -> None:
        self._id = value


class LogParser:
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(LogParser, cls).__new__(cls)
        return cls._instance

    @staticmethod
    def get_instance() -> 'LogParser':
        return LogParser._instance


class SendLogRequest:
    pass


def mocked_append_entry(request: AppendEntryRequest) -> long:
    # TO DO: implement the logic to handle AppendEntryRequest here
    pass


def mocked_append_entries(request: AppendEntriesRequest) -> long:
    # TO DO: implement the logic to handle AppendEntriesRequest here
    pass


class LogDispatcherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raft_member = TestMetaGroupMember()
        self.appended_entries = {}
        self.down_node = set()

    def test_async(self) -> None:
        # TO DO: implement the logic to handle async log dispatch here
        pass

    def test_sync(self) -> None:
        # TO DO: implement the logic to handle sync log dispatch here
        pass

    def test_with_failure(self) -> None:
        for i in range(1, 4):
            self.down_node.add(TestUtils.get_node(i))
        dispatcher = LogDispatcher()
        try:
            logs = TestUtils.prepare_test_logs(10)
            for log in logs:
                request = self.raft_member.build_send_log_request(log)
                dispatcher.offer(request)
            while not check_result(logs, 6):
                # wait
                pass
        finally:
            dispatcher.close()

    def test_with_large_log(self) -> None:
        IoTDBDescriptor.get_instance().get_config().set_thrift_max_frame_size(64 * 1024 + IoTDBConstant.LEFT_SIZE_IN_REQUEST)
        for i in range(1, 4):
            self.down_node.add(TestUtils.get_node(i))
        dispatcher = LogDispatcher()
        try:
            logs = TestUtils.prepare_large_test_logs(20)
            for log in logs:
                request = self.raft_member.build_send_log_request(log)
                dispatcher.offer(request)
            while not check_result(logs, 6):
                # wait
                pass
        finally:
            dispatcher.close()

    def test_with_down_node(self) -> None:
        for i in range(1, 4):
            self.down_node.add(TestUtils.get_node(i))
        dispatcher = LogDispatcher()
        try:
            logs = TestUtils.prepare_test_logs(10)
            for log in logs:
                request = self.raft_member.build_send_log_request(log)
                dispatcher.offer(request)
            while not check_result(logs, 6):
                # wait
                pass
        finally:
            dispatcher.close()

    def tearDown(self) -> None:
        self.raft_member.stop()
        self.raft_member.close_log_manager()


if __name__ == '__main__':
    unittest.main()
