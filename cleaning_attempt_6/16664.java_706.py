import threading
import time

class CommitLogCallbackTest:

    def test(self):
        raft_member = TestMetaGroupMember()
        commit_log_callback = CommitLogCallback(raft_member)
        lock = raft_member.get_sync_lock()

        def callback():
            commit_log_callback.on_complete(None)

        thread = threading.Thread(target=callback)
        thread.start()
        lock.acquire()
        lock.wait_for(lambda: not lock.locked())
        assert True
        raft_member.stop()

    @staticmethod
    def tearDown():
        EnvironmentUtils.clean_all_dir()


class CommitLogCallback:
    pass


class TestMetaGroupMember:
    def __init__(self):
        self.get_sync_lock = lambda: threading.Lock()
