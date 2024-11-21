import threading
import time
from unittest import TestCase

class SnapshotCatchUpHandlerTest(TestCase):

    def test_complete(self):
        succeeded = [False]
        receiver = {'id': 0}
        handler = SnapshotCatchUpHandler(succeeded, receiver, None)
        
        def complete():
            handler.onComplete(None)

        threading.Thread(target=complete).start()
        while not succeeded[0]:
            time.sleep(0.01) # wait for the thread to finish
        self.assertTrue(succeeded[0])

    def test_error(self):
        succeeded = [False]
        receiver = {'id': 0}
        handler = SnapshotCatchUpHandler(succeeded, receiver, None)
        
        def error():
            handler.onError(TestException())

        threading.Thread(target=error).start()
        while not succeeded[0]:
            time.sleep(0.01) # wait for the thread to finish
        self.assertFalse(succeeded[0])

class TestException(Exception):
    pass

class SnapshotCatchUpHandler:
    def __init__(self, succeeded, receiver, null):
        self.succeeded = succeeded
        self.receiver = receiver
        self.null = null

    def onComplete(self, none):
        with lock: # assuming you have a global lock variable defined elsewhere in your code
            self.succeeded[0] = True

    def onError(self, exception):
        with lock:
            self.succeeded[0] = False
