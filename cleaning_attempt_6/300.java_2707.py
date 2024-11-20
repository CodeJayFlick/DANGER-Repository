import threading
from functools import partial

class DebouncedRowWrappedEnumeratedColumnTableModel:
    def __init__(self, name, col_type, key_func, wrapper):
        self.debouncer = Debounce(100)
        super().__init__(name, col_type, key_func, wrapper)

        self.debouncer.add_listener(self.settled)

    @property
    def debouncer(self):
        return self._debouncer

    @debouncer.setter
    def debouncer(self, value):
        if not isinstance(value, Debounce):
            raise TypeError("Debouncer must be an instance of Debounce")
        self._debouncer = value

    def fire_table_data_changed(self):
        self.debouncer.contact(None)

    def fire_table_cell_updated(self, row, column):
        self.debouncer.contact(None)

    def fire_table_rows_deleted(self, first_row, last_row):
        self.debouncer.contact(None)

    def fire_table_rows_inserted(self, first_row, last_row):
        self.debouncer.contact(None)

    def fire_table_rows_updated(self, first_row, last_row):
        self.debouncer.contact(None)

    # NB. Let structure changes get processed immediately

    def settled(self, __):
        threading.runLater(partial(super().fire_table_data_changed))

class Debounce:
    def __init__(self, delay):
        if not isinstance(delay, int) or delay < 0:
            raise ValueError("Delay must be a non-negative integer")
        self.delay = delay
        self.lock = threading.Lock()
        self.event = threading.Event()

    @property
    def event(self):
        return self._event

    @event.setter
    def event(self, value):
        if not isinstance(value, threading.Event):
            raise TypeError("Event must be an instance of Event")
        self._event = value

    def add_listener(self, listener):
        with self.lock:
            self.event.clear()
            self.event.set()

    def contact(self, __):
        with self.lock:
            while True:
                if not self.event.is_set():
                    break
                self.event.wait(self.delay)
