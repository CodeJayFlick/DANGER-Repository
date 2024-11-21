import threading
from AtomicInteger import AtomicInteger

class Peer:
    def __init__(self, next_index):
        self.next_index = next_index
        self.match_index = -1
        self.inconsistent_heartbeat_num = AtomicInteger(0)
        self.last_heart_beat_index = None

    @property
    def next_index(self):
        return self._next_index

    @next_index.setter
    def next_index(self, value):
        self._next_index = value

    @property
    def match_index(self):
        return self._match_index

    @match_index.setter
    def match_index(self, value):
        self._match_index = value
        self.next_index = max(self.next_index, self.match_index + 1)
        threading.Thread(target=self.notify_all).start()

    def notify_all(self):
        # equivalent to Java's notifyAll()
        pass

    @property
    def inconsistent_heartbeat_num(self):
        return self._inconsistent_heartbeat_num.get()

    @inconsistent_heartbeat_num.setter
    def inconsistent_heartbeat_num(self, value):
        self._inconsistent_heartbeat_num.set(value)

    def inc_inconsistent_heartbeat_num(self):
        return self.inconsistent_heartbeat_num.incrementAndGet()

    def reset_inconsistent_heartbeat_num(self):
        self.inconsistent_heartbeat_num.set(0)

    @property
    def last_heart_beat_index(self):
        return self._last_heart_beat_index

    @last_heart_beat_index.setter
    def last_heart_beat_index(self, value):
        self._last_heart_beat_index = value
