Here is the translation of the given Java code into Python:

```Python
class DataTypePropertyManager:
    def __init__(self):
        self.change_listeners = set()
        self.recently_used_key_stroke = None
        self.recently_used_data_type = None
        self.recently_used_dt_id = 0

    def remove(self, data_type: 'DataType') -> None:
        if self.is_recently_used(data_type):
            self.recently_used_data_type = None
        notify_listeners()

    def data_type_renamed(self, data_type: 'DataType') -> None:
        if self.is_favorite(data_type) or self.is_recently_used(data_type):
            notify_listeners()

    def is_recently_used(self, data_type: 'DataType') -> bool:
        return (self.recently_used_data_type and
                self.recently_used_data_type == data_type)

    def is_favorite(self, data_type: 'DataType') -> bool:
        # This method should be implemented based on the actual logic of your program.
        pass

    def set_recently_used(self, data_type: 'DataType') -> None:
        if (data_type != self.recently_used_data_type and
                not data_type.is_deleted()):
            self.recently_used_data_type = data_type
            self.recently_used_dt_id = 0  # This should be implemented based on the actual logic of your program.
            return True

    def get_recently_used(self) -> 'DataType':
        return self.recently_used_data_type

    def get_key_stroke_for_recently_used(self) -> None:
        return self.recently_used_key_stroke

    def program_opened(self, program: 'Program') -> None:
        self.program_data_types_manager = program.listing.get_data_type_manager()

    def program_closed(self, program: 'Program') -> None:
        self.recently_used_data_type = None
        self.program_data_types_manager = None

    def domain_object_restored(self, data_type_manager_domain_object) -> None:
        if (self.recently_used_data_type and
                self.recently_used_data_type.get_data_type_manager() == self.program_data_types_manager):
            self.recently_used_data_type = self.program_data_types_manager.get_data_type(self.recently_used_dt_id)
        notify_listeners()

    def add_change_listener(self, l: 'ChangeListener') -> None:
        self.change_listeners.add(l)

    def remove_change_listener(self, l: 'ChangeListener') -> None:
        self.change_listeners.remove(l)

    def notify_listeners(self) -> None:
        if not self.change_listeners:
            return
        run_swing_now(lambda: [l.state_changed(ChangeEvent(self)) for l in self.change_listeners])

def run_swing_now(func):
    import threading

    event_queue = threading.Event()
    result = []

    def wrapper():
        try:
            result.append(func())
        finally:
            event_queue.set()

    thread = threading.Thread(target=wrapper)
    thread.start()
    event_queue.wait()
    return result[0] if result else None
```

Please note that this translation is not a direct conversion, but rather an equivalent Python code. The Java code uses various libraries and frameworks (like Swing) which are not directly translatable to Python.