from collections import defaultdict, deque
import time
import threading


class AsyncPairingCache:
    def __init__(self, concurrency_level, timeout_milliseconds, max_pending):
        self.results = {}
        self.promises = {}

        for _ in range(concurrency_level):
            queue = deque()
            self.results[queue] = defaultdict(dict)
            self.promises[queue] = defaultdict(dict)

        self.timeout_milliseconds = timeout_milliseconds
        self.max_pending = max_pending

    def result_removed(self, key, value):
        pass  # Implement this method as needed

    def promise_removed(self, key, future):
        if not isinstance(future, threading.Future):
            raise ValueError("Future must be a threading Future")
        try:
            future.set_exception(RuntimeError("Promise with key {} was evicted".format(key)))
        except Exception as e:
            print(e)

    def wait_on(self, key):
        return self.wait_on(key, lambda k: threading.Event())

    def wait_on(self, key, factory):
        value = self.results.get(key)
        if value is not None:
            future = threading.Event()
            for queue in list(self.promises.keys()):
                del self.promises[queue][key]
                break
            return future

        future = factory(key)

        while True:
            try:
                time.sleep(0.1)  # Sleep a little bit to avoid busy waiting
                if key not in self.results or value is None:
                    break
            except Exception as e:
                print(e)
        for queue in list(self.promises.keys()):
            del self.promises[queue][key]
            break

        return future

    def fulfill(self, key, value):
        promise = self.promises.get(key)

        if promise is not None:
            for queue in list(promise.keys()):
                del promise[queue]

        self.results[key] = value
        return

    def flush(self, exc):
        copy = set()
        with lock:
            copy.update(list(self.promises.values()))
            self.promises.clear()
            self.results.clear()

        for p in copy:
            try:
                p.set_exception(exc)
            except Exception as e:
                print(e)

    @property
    def unpaired_promises(self):
        return {k: v.copy() for k, v in list(self.promises.items())}

    @property
    def unpaired_results(self):
        return self.results.copy()


lock = threading.Lock()
