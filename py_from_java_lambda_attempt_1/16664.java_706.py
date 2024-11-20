Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the `CommitLogCallback` and `TestMetaGroupMember` classes, as they were not provided in the original Java code. In particular:

* The `CommitLogCallback` class is assumed to have an `on_complete` method.
* The `TestMetaGroupMember` class is assumed to have a `get_sync_lock` method that returns a lock object.

Also, I used Python's built-in `threading` module instead of Java's equivalent.