import threading
import time
from queue import Queue
from logging import getLogger, Logger

class ReaderWriterLock:
    def __init__(self):
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()

    def read_lock(self):
        return self.read_lock

    def write_lock(self):
        return self.write_lock


class Writer(threading.Thread):
    def __init__(self, name, lock):
        super().__init__()
        self.name = name
        self.lock = lock

    def run(self):
        with self.lock:
            print(f"{self.name} begin")
            time.sleep(1)
            print(f"{self.name} finish")


class Reader(threading.Thread):
    def __init__(self, name, lock):
        super().__init__()
        self.name = name
        self.lock = lock

    def run(self):
        with self.lock:
            print(f"{self.name} begin")
            time.sleep(1)
            print(f"{self.name} finish")


def test_read_and_write():
    reader_writer_lock = ReaderWriterLock()
    writer = Writer("Writer 1", reader_writer_lock.write_lock())
    reader = Reader("Reader 1", reader_writer_lock.read_lock())

    queue = Queue()

    def execute_service(func):
        func.start()
        while not queue.empty():
            result = queue.get()
            print(result)
        return

    thread_pool = []
    for i in range(2):
        if i == 0:
            thread_pool.append(writer)
        else:
            thread_pool.append(reader)

    for t in thread_pool:
        execute_service(t)

    time.sleep(1)


def test_write_and_read():
    reader_writer_lock = ReaderWriterLock()
    writer = Writer("Writer 1", reader_writer_lock.write_lock())
    reader = Reader("Reader 1", reader_writer_lock.read_lock())

    queue = Queue()

    def execute_service(func):
        func.start()
        while not queue.empty():
            result = queue.get()
            print(result)
        return

    thread_pool = []
    for i in range(2):
        if i == 0:
            thread_pool.append(writer)
        else:
            thread_pool.append(reader)

    for t in thread_pool:
        execute_service(t)


if __name__ == "__main__":
    test_read_and_write()
    test_write_and_read()

