import random
import time
from threading import current_thread

class TryLoopState:
    def __init__(self, retry_error_message_supplier, config):
        self.retry_error_message_supplier = retry_error_message_supplier
        self.max_time = config.commit_timeout * 1000  # convert milliseconds to seconds
        self.max_retries = config.commit_retries
        self.monotonic_clock = DefaultMonotonicClock()
        self.t0 = time.time()

    @classmethod
    def new_try_loop_state(cls, retry_error_message_supplier, config):
        return cls(retry_error_message_supplier, config)

    def success(self, result):
        return result

    def retry(self):
        self.retries += 1

        current_time = time.time()
        elapsed_time = current_time - self.t0

        if self.max_time < elapsed_time or self.max_retries <= self.retries:
            raise ReferenceRetryFailureException(self.retry_error_message_supplier())

        sleep_millis = random.randint(5, 25) * 2 ** (self.retries.bit_length() // 10)
        # Prevent that we "sleep" too long and exceed 'max_time'
        sleep_millis = min((self.max_time - elapsed_time) / 1000, sleep_millis)

        time.sleep(sleep_millis / 1000)

        self.lower_bound *= 2
        self.upper_bound *= 2

    def close(self):
        pass


class MonotonicClock:
    @classmethod
    def current_nanos(cls):
        return int(time.time() * 1e9 + time.thread_time()[0])

    @classmethod
    def sleep_millis(cls, nanos):
        try:
            time.sleep(nanos / 1000000)
        except KeyboardInterrupt as e:
            if current_thread().is_alive():
                raise


class DefaultMonotonicClock(MonotonicClock):
    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self):
        pass

    @classmethod
    def current_nanos(cls):
        return int(time.time() * 1e9 + time.thread_time()[0])

    @classmethod
    def sleep_millis(cls, nanos):
        try:
            time.sleep(nanos / 1000000)
        except KeyboardInterrupt as e:
            if current_thread().is_alive():
                raise


class ReferenceRetryFailureException(Exception):
    pass

# usage example:

def retry_error_message_supplier():
    return "Error message"

config = {"commit_timeout": 10, "commit_retries": 5}

try_loop_state = TryLoopState.new_try_loop_state(retry_error_message_supplier, config)

while True:
    try:
        # your operation here
        pass
    except Exception as e:
        try_loop_state.retry()
