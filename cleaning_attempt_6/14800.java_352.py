import threading
import logging

class ReaderWriterLock:
    def __init__(self):
        self.reader_mutex = threading.Lock()
        self.current_reader_count = 0
        self.global_mutex = set()

    @property
    def read_lock(self):
        return ReadLock(self)

    @property
    def write_lock(self):
        return WriteLock(self)


class ReadLock:
    def __init__(self, reader_writer_lock):
        self.reader_writer_lock = reader_writer_lock

    def acquire_for_readers(self):
        with self.reader_writer_lock.reader_mutex:
            if not self.reader_writer_lock.global_mutex:
                self.reader_writer_lock.current_reader_count += 1
                return
            while any(isinstance(x, WriteLock) for x in self.reader_writer_lock.global_mutex):
                try:
                    self.reader_writer_lock.reader_mutex.wait()
                except threading.InterruptError as e:
                    logging.info("InterruptedException while waiting for globalMutex to begin reading", e)
                    raise

    def lock(self):
        with self.reader_writer_lock.reader_mutex:
            if not self.reader_writer_lock.current_reader_count:
                self.acquire_for_readers()

    def unlock(self):
        with self.reader_writer_lock.reader_mutex:
            self.reader_writer_lock.current_reader_count -= 1
            if not self.reader_writer_lock.current_reader_count:
                with self.reader_writer_lock.global_mutex:
                    try:
                        self.reader_writer_lock.reader_mutex.notify_all()
                    except threading.InterruptError as e:
                        logging.info("InterruptedException while waiting for globalMutex to end reading", e)
                        raise


class WriteLock:
    def __init__(self, reader_writer_lock):
        self.reader_writer_lock = reader_writer_lock

    def lock(self):
        with self.reader_writer_lock.global_mutex:
            if any(isinstance(x, ReadLock) for x in self.reader_writer_lock.global_mutex):
                try:
                    self.reader_writer_lock.global_mutex.wait()
                except threading.InterruptError as e:
                    logging.info("InterruptedException while waiting for globalMutex to begin writing", e)
                    raise
            else:
                self.reader_writer_lock.global_mutex.add(self)

    def unlock(self):
        with self.reader_writer_lock.global_mutex:
            try:
                self.reader_writer_lock.global_mutex.remove(self)
                self.reader_writer_lock.global_mutex.notify_all()
            except threading.InterruptError as e:
                logging.info("InterruptedException while waiting for globalMutex to end writing", e)
                raise
