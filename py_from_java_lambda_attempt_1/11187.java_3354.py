Here's your Java interface translated into Python:

```Python
class DomainObject:
    def __init__(self):
        self._undo_lock = object()
        self._domain_file = None
        self._temporary_state = False
        self._changeable = True
        self._can_save = True

    @property
    def undo_lock(self):
        return self._undo_lock

    @property
    def domain_file(self):
        return self._domain_file

    @domain_file.setter
    def domain_file(self, value):
        self._domain_file = value

    @property
    def temporary_state(self):
        return self._temporary_state

    @temporary_state.setter
    def temporary_state(self, state):
        if not isinstance(state, bool):
            raise ValueError("Temporary state must be a boolean")
        self._temporary_state = state

    @property
    def changeable(self):
        return self._changeable

    @changeable.setter
    def changeable(self, value):
        if not isinstance(value, bool):
            raise ValueError("Changeability must be a boolean")
        self._changeable = value

    @property
    def can_save(self):
        return self._can_save

    @can_save.setter
    def can_save(self, value):
        if not isinstance(value, bool):
            raise ValueError("Save capability must be a boolean")
        self._can_save = value

    def is_changed(self) -> bool:
        pass  # Implement this method in your subclass

    def set_temporary(self, state: bool) -> None:
        pass  # Implement this method in your subclass

    def save(self, comment: str, monitor: TaskMonitor) -> None:
        raise NotImplementedError("Method must be implemented by the subclass")

    def save_to_packed_file(self, file: File, monitor: TaskMonitor) -> None:
        raise NotImplementedError("Method must be implemented by the subclass")

    def release(self, consumer: object) -> None:
        pass  # Implement this method in your subclass

    def add_listener(self, dol: DomainObjectListener) -> None:
        pass  # Implement this method in your subclass

    def remove_listener(self, dol: DomainObjectListener) -> None:
        pass  # Implement this method in your subclass

    def get_domain_file(self) -> 'DomainFile':
        return self._domain_file

    def add_consumer(self, consumer: object) -> bool:
        if not isinstance(consumer, type):
            raise ValueError("Consumer must be an instance of a class")
        pass  # Implement this method in your subclass

    def get_consumer_list(self) -> list:
        pass  # Implement this method in your subclass

    def is_used_by(self, consumer: object) -> bool:
        if not isinstance(consumer, type):
            raise ValueError("Consumer must be an instance of a class")
        return False  # Default implementation returns false

    @property
    def events_enabled(self):
        pass  # Implement this method in your subclass

    @events_enabled.setter
    def events_enabled(self, enabled: bool) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("Events enablement must be a boolean")
        self._events_enabled = enabled

    @property
    def sending_events(self):
        return True  # Default implementation returns true

    def flush_events(self) -> None:
        pass  # Implement this method in your subclass

    def can_lock(self) -> bool:
        return False  # Default implementation always allows locking

    @property
    def is_locked(self):
        return False  # Default implementation always reports unlocked state

    def lock(self, reason: str) -> bool:
        if not isinstance(reason, str):
            raise ValueError("Reason must be a string")
        self._is_locked = True
        return True  # Default implementation allows locking

    def force_lock(self, rollback: bool, reason: str) -> None:
        pass  # Implement this method in your subclass

    def unlock(self) -> None:
        if not hasattr(self, '_is_locked'):
            raise AttributeError("Domain object is not locked")
        self._is_locked = False
```

Please note that Python does not support interfaces like Java. Instead, we can use abstract classes or protocols to define the interface for a class hierarchy.

Also, some methods in your original code are missing their implementations and have been left as `pass` statements. These should be implemented according to the requirements of your domain object.