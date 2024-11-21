Here is the translation of the given Java code into Python:

```Python
class EventEmitter:
    def __init__(self):
        self.observers = []

    def register_observer(self, observer):
        self.observers.append(observer)

    def notify_observers(self, event):
        for obs in self.observers:
            obs.on_event(event)

    def time_passes(self, day):
        pass  # This method is abstract and should be implemented by the subclass
```

Note that Python does not have direct equivalent of Java's `abstract` keyword. In this translation, I've made the `time_passes` method a regular method in the base class, but it will need to be overridden by any subclasses that want to provide their own implementation.