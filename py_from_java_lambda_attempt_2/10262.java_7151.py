Here's how you can implement this interface in Python:

```Python
class GhidraTimer:
    def __init__(self):
        self.is_running = False
        self.repeats = False
        self.delay = 0
        self.initial_delay = 0
        self.timer_callback = None

    def start(self):
        self.is_running = True

    def stop(self):
        self.is_running = False

    def setDelay(self, delay):
        self.delay = delay

    def setInitialDelay(self, initial_delay):
        self.initial_delay = initial_delay

    def setRepeats(self, repeats):
        self.repeats = repeats

    def isRepeats(self):
        return self.repeats

    def isRunning(self):
        return self.is_running

    def getDelay(self):
        return self.delay

    def getInitialDelay(self):
        return self.initial_delay

    def setTimerCallback(self, callback):
        self.timer_callback = callback
```

This Python class implements the same methods as the Java interface. Note that there is no direct equivalent of interfaces in Python; instead, you can use abstract base classes or protocols to define a common API for your objects.