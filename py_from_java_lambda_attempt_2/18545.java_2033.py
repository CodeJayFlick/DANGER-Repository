Here is the equivalent Python code:

```Python
class Timer:
    _timers = {}
    _enabled = False

    @classmethod
    def start(cls, timer_name):
        if not cls._enabled:
            return
        cls._timers[timer_name] = {"start_time": int(time.time())}

    @classmethod
    def stop(cls, timer_name):
        if not cls._enabled:
            return 0

        info = cls._timers.get(timer_name)
        if info is None:
            raise ValueError(f"Could not find timer {timer_name}")

        stop_time = int(time.time())
        info["stop_time"] = stop_time
        info["duration"] = stop_time - info["start_time"]

    @classmethod
    def get_timers(cls):
        return cls._timers

    @classmethod
    def get_timer(cls, timer_name):
        return cls._timers.get(timer_name)

    @classmethod
    def enable(cls):
        cls._enabled = True

    @classmethod
    def disable(cls):
        cls._enabled = False


class TimerInfo:
    def __init__(self, start_time):
        self.start_time = start_time
        self.stop_time = None
        self.duration = 0

    def stop(self, stop_time):
        self.stop_time = stop_time
        self.duration = self.stop_time - self.start_time

    @property
    def get_start_time(self):
        return self.start_time

    @property
    def get_stop_time(self):
        return self.stop_time


    @property
    def get_duration(self):
        return self.duration
```

Note that Python does not have a direct equivalent to Java's `volatile` keyword, which is used in the original code. The `_enabled` and `_timers` variables are class-level attributes, but they do not need to be declared as volatile because Python uses a Global Interpreter Lock (GIL) to ensure thread safety.