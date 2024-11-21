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
