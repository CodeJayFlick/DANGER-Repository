from collections import defaultdict, deque
import weakref

class Change:
    ADDED = 1
    MODIFIED = 2
    REMOVED = 3

def then(one: int, two: int) -> int:
    if one == Change.ADDED and two in (Change.MODIFIED, Change.REMOVED):
        return Change.REMOVED
    elif one == Change.MODIFIED and two in (Change.ADDED, Change.MODIFIED):
        return Change.MODIFIED
    else:
        return two

class ChangeSet:
    def __init__(self):
        self.changes = defaultdict(int)

    def element_added(self, e: object) -> None:
        self.changes[e] = Change.ADDED

    def element_modified(self, e: object) -> None:
        self.changes[e] = Change.MODIFIED

    def element_removed(self, e: object) -> None:
        self.changes[e] = Change.REMOVED


class DefaultObservableCollection:
    class ListenerSet:
        def __init__(self):
            self.listeners = set()

        def add(self, listener: callable) -> None:
            self.listeners.add(weakref.ref(listener))

        def remove(self, listener: weakref.ReferenceType) -> None:
            if listener in self.listeners:
                self.listeners.remove(listener)

    class ChangeAggregator:
        aggregator_count = 0

        def __init__(self):
            DefaultObservableCollection.ChangeAggregator.aggregator_count += 1
            self.l = changes
            self.lock = lock

        def close(self) -> None:
            if DefaultObservableCollection.ChangeAggregator.aggregator_count == 1:
                l = listeners.fire
                changes.fire()

    def __init__(self, wrapped: list, listener_class):
        self.wrapped = wrapped
        self.listeners = DefaultObservableCollection.ListenerSet()
        self.l = self.listeners.fire
        self.lock = object()
        self.changes = ChangeSet()
        self.aggregator_count = 0

    @property
    def decorated(self) -> list:
        return self.wrapped[:]

    def add_listener(self, listener: callable) -> None:
        self.listeners.add(listener)

    def remove_listener(self, listener: weakref.ReferenceType) -> None:
        if listener in self.listeners:
            self.listeners.remove(listener)

    def __iter__(self):
        for e in self.wrapped:
            yield e

    def add(self, e: object) -> bool:
        return e not in self.wrapped and self.wrapped.append(e)

    def remove(self, o: object) -> None:
        if isinstance(o, type) and issubclass(o, object):
            for i, e in enumerate(list(self)):
                if isinstance(e, o):
                    del self[i]

    def add_all(self, c: list) -> bool:
        added = False
        for e in c:
            added |= self.add(e)
        return added

    def remove_all(self, c: list) -> None:
        for o in c:
            if isinstance(o, type) and issubclass(o, object):
                for i, e in enumerate(list(self)):
                    if isinstance(e, o):
                        del self[i]

    def retain_all(self, c: set) -> bool:
        removed = False
        it = iter(self)
        while True:
            try:
                e = next(it)
            except StopIteration:
                break
            if not c.issuperset({e}):
                removed |= self.remove(e)
        return removed

    def clear(self) -> None:
        for _ in list(self):
            pass

    def notify_added(self, e: object) -> None:
        self.l.elementAdded(e)

    def notify_modified(self, e: object) -> None:
        if e in self.wrapped:
            self.l.elementModified(e)

    def notify_removed(self, e: object) -> None:
        self.l.elementRemoved(e)

    def aggregate_changes(self) -> DefaultObservableCollection.ChangeAggregator:
        return DefaultObservableCollection.ChangeAggregator()
