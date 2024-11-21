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
