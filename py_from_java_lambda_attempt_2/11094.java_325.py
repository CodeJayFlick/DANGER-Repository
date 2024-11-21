Here is the translation of the given Java code into Python:

```Python
import logging

class FVEventListener:
    def __init__(self):
        self._observers = []

    def add_observer(self, observer):
        if not isinstance(observer, (list, tuple)):
            raise TypeError("Observer must be a list or tuple")
        for obs in observer:
            if not callable(obs):
                raise ValueError(f"Each element of the observer list/tuple must be callable. Got {obs}")
        self._observers.extend(list(observer))

    def remove_observer(self, observer):
        try:
            self._observers.remove(observer)
        except ValueError as e:
            logging.error(e)

    def notify_observers(self, *args, **kwargs):
        for obs in self._observers[:]:
            if len(args) > 0 and callable(obs[1]):
                obs[1](*args, **kwargs)
            elif len(kwargs) > 0 and callable(obs[2]):
                obs[2](**kwargs)

    def send(self, *args, **kwargs):
        self._observers = []
        set_changed()
        notify_observers(*args, **kwargs)


def main():
    # Example usage
    listener = FVEventListener()

    class MyObserver:
        def __init__(self):
            pass

        def update(self, *args, **kwargs):
            print(f"Received event: {args}, {kwargs}")

    observer1 = MyObserver()
    observer2 = MyObserver()

    listener.add_observer([observer1.update, observer2.update])

    # Simulate sending an event
    listener.send("Hello", foo="bar")

if __name__ == "__main__":
    main()
```

This Python code is a direct translation of the given Java code. It provides similar functionality to the original Java class: it allows you to add and remove observers, notify them when events occur, and send those events with custom data.