Here is the translation of the given Java code into Python:

```Python
class Observable:
    def __init__(self):
        self.observers = []

    def add_observer(self, observer):
        self.observers.append(observer)

    def remove_observer(self, observer):
        if observer in self.observers:
            self.observers.remove(observer)

    def notify_observers(self, argument):
        for observer in self.observers:
            observer.update(self, argument)
```

Note that Python does not have direct equivalents to Java's generics or `List` class. Instead, we use a list of observers and check if an observer is present before removing it from the list.