import threading
import time
from queue import Queue
from logging import getLogger, Logger

class WriterTest:
    def __init__(self):
        self.appender = InMemoryAppender()

    def setUp(self):
        self.appender.start()

    def tearDown(self):
        self.appender.stop()

    logger: Logger = getLogger(__name__)

    @staticmethod
    def test_write():
        lock = threading.Lock()
        writers = [Writer("Writer 1", lock), Writer("Writer 2", lock)]
        writer_threads = []

        for i, writer in enumerate(writers):
            thread = threading.Thread(target=writer.write)
            thread.start()
            writer_threads.append(thread)

        time.sleep(0.15)  # Let write1 execute first
        writers[1].write()  # Start writing2

        for thread in writer_threads:
            thread.join()

        self.assertTrue(self.appender.logContains("Writer 1 begin"))
        self.assertTrue(self.appender.logContains("Writer 1 finish"))
        self.assertTrue(self.appender.logContains("Writer 2 begin"))
        self.assertTrue(self.appender.logContains("Writer 2 finish"))

class Writer:
    def __init__(self, name: str, lock):
        self.name = name
        self.lock = lock

    def write(self):
        with self.lock:
            time.sleep(0.25)  # Simulate writing operation
            print(f"{self.name} begin")
            time.sleep(0.1)
            print(f"{self.name} finish")

class InMemoryAppender:
    def __init__(self, writer_class=None):
        self.log = []
        if writer_class is not None:
            for _ in range(writer_class.__name__):
                self.log.append("")

    def start(self):
        pass

    def stop(self):
        pass

    def logContains(self, text: str) -> bool:
        return text in self.log
