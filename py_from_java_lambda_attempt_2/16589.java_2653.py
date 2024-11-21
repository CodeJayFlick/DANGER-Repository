Here's your Java code translated into Python:

```Python
class NodeStatus:
    def __init__(self):
        self.status = None
        self.last_update_time = 0
        self.last_response_latency = 0
        self.is_activated = True
        self.last_deactivated_time = 0

    DEACTIVATION_VALID_INTERVAL_MS = 600000L

    def compareTo(self, other):
        return (self.last_response_latency - other.last_response_latency)

    def __eq__(self, other):
        if self is other:
            return True
        elif not isinstance(other, NodeStatus) or type(self).__name__ != type(other).__name__':
            return False
        else:
            return self.last_update_time == other.last_update_time and \
                   self.last_response_latency == other.last_response_latency and \
                   self.status == other.status

    def __hash__(self):
        return hash((self.status, self.last_update_time, self.last_response_latency))

    @property
    def last_update_time(self):
        return self._last_update_time

    @last_update_time.setter
    def last_update_time(self, value):
        self._last_update_time = value

    @property
    def last_response_latency(self):
        return self._last_response_latency

    @last_response_latency.setter
    def last_response_latency(self, value):
        self._last_response_latency = value

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    def set_status(self, value):
        self.status = value

    def set_last_update_time(self, value):
        self.last_update_time = value

    def set_last_response_latency(self, value):
        self.last_response_latency = value

    def activate(self):
        self.is_activated = True

    def deactivate(self):
        self.is_activated = False
        self.last_deactivated_time = int(time.time())

    @property
    def is_activated(self):
        return self._is_activated or (int(time.time()) - self.last_deactivated_time) > NodeStatus.DEACTIVATION_VALID_INTERVAL_MS

    @is_activated.setter
    def is_activated(self, value):
        self._is_activated = value

    @property
    def last_deactivated_time(self):
        return self._last_deactivated_time

    @last_deactivated_time.setter
    def last_deactivated_time(self, value):
        self._last_deactivated_time = value
```

Note that Python does not have an exact equivalent to Java's `@Override` annotation. However, I've kept the method names and signatures identical in this translation for clarity purposes.