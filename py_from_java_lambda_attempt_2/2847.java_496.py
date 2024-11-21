Here is the translation of the given Java interface into a Python equivalent:

```Python
from typing import TypeVar, Generic, Collection

class ObservableCollection(Generic[E], Collection[E]):
    def add_listener(self, listener: 'CollectionChangeListener[super E]'):
        pass  # implement this method in your subclass

    def remove_listener(self, listener: 'CollectionChangeListener[super E]'):
        pass  # implement this method in your subclass

    def notify_modified(self, element: E):
        pass  # implement this method in your subclass

class ChangeAggregator:
    def close(self) -> None:
        pass  # implement this method in your subclass
```

Please note that Python does not have direct equivalent of Java's interfaces. Instead, we can use abstract classes or protocols (in the context of type hinting). The above code is a translation into an abstract class with methods declared as `pass`, which means they are placeholders and need to be implemented in any subclass.

Also, I used the Python 3.x style for typing hints (`TypeVar` from `typing` module) and generic types.