Here is the translation of the given Java code into equivalent Python:

```Python
class SkriptTimings:
    enabled = False
    _skript = None

    def start(self, name):
        if not self.enabled:  # Timings disabled :(
            return None
        timing = Timings.of(_skript, name)
        timing.start_timing_if_sync()  # No warning spam in async code
        assert timing is not None
        return timing

    @staticmethod
    def stop(timing):
        if timing is None:  # Timings disabled...
            return
        (timing).stop_timing_if_sync()

    @property
    def enabled(self):
        # First check if we can run timings (enabled in settings + running Paper)
        # After that (we know that class exists), check if server has timings running
        return self.enabled and Timings.is_timings_enabled()

    @enabled.setter
    def enabled(self, flag):
        self.enabled = flag

    @property
    def skript(self):
        return self._skript

    @skript.setter
    def set_skript(self, plugin):
        self._skript = plugin
```

Note that Python does not have a direct equivalent to Java's `@Nullable` annotation. Instead, we can use the fact that in Python, `None` is used as the default return value for functions and methods with no explicit return statement.

Also note that Python has its own way of handling properties (getters and setters), which are implemented using special methods (`__getattr__`, `__setattr__`) or decorators. In this case, we use a property decorator to define getter and setter methods for the `enabled` and `skript` attributes.