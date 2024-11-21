import threading
from collections import deque
from weakref import WeakSet


class DomainObjectChangeSupport:
    def __init__(self, src, time_interval, bufsize):
        self.src = src
        self.domain_object_lock = threading.Lock()
        self.write_lock = threading.Lock("DOCS Change Records Queue Lock")
        self.is_disposed = False

        self.listeners = WeakSet()
        self.changes_queue = deque(maxlen=bufsize)
        self.timer = GhidraTimer(time_interval, time_interval)

    def add_listener(self, listener):
        pending_event = convert_event_queue_records_to_event()
        previous_listeners = atomic_add_listener(listener)

        SystemUtilities.run_if_swing_or_post_swing_later(
            lambda: notify_event(previous_listeners, pending_event)
        )

    def remove_listener(self, listener):
        self.listeners.remove(listener)

    def send_event_now(self):
        event = convert_event_queue_records_to_event()
        if event is not None:
            notify_event(self.listeners, event)

    def convert_event_queue_records_to_event(self):
        with self.write_lock:
            if len(self.changes_queue) == 0:
                self.timer.stop()
                return None

            event = DomainObjectChangedEvent(self.src, list(self.changes_queue))
            self.changes_queue.clear()

            return event

    def notify_event(self, listeners_to_notify, ev):
        if ev is not None and not self.is_disposed:
            for listener in listeners_to_notify:
                try:
                    listener.domain_object_changed(ev)
                except Exception as exc:
                    Msg.show_error(None, "Error", "Error in Domain Object listener", str(exc))

    def flush(self):
        lock_owner = self.domain_object_lock._owner
        if lock_owner == threading.current_thread():
            raise ValueError("Cannot call flush() with locks!")

        SystemUtilities.run_swing_now(lambda: send_event_now())

    def fire_event(self, docr):
        if self.is_disposed:
            return

        with self.write_lock:
            self.changes_queue.append(docr)
            self.timer.start()

    def fatalErrorOccurred(self, t):
        listeners_copy = list(self.listeners)

        dispose()

        error_task = lambda: notify_domain_object_changed(listeners_copy, DomainObjectChangedEvent(self.src, [DomainObjectChangeRecord(DomainObject.DO_OBJECT_ERROR, None, t)]))

        SystemUtilities.run_swing_later(error_task)

    def dispose(self):
        with self.write_lock:
            self.is_disposed = True
            self.timer.stop()
            self.changes_queue.clear()

        self.listeners.clear()


class DomainObjectChangedEvent:
    def __init__(self, src, changes_queue):
        self.src = src
        self.changes_queue = changes_queue


class DomainObjectChangeRecord:
    DO_OBJECT_ERROR = 0

    def __init__(self, type, old_value, new_value):
        self.type = type
        self.old_value = old_value
        self.new_value = new_value


def atomic_add_listener(self, l):
    previous_listeners = list(self.listeners)
    for listener in self.listeners:
        previous_listeners.append(listener)

    self.listeners.add(l)

    return previous_listeners

# Lock Methods
class GhidraTimer:
    def __init__(self, time_interval, initial_delay=0, delay=500, repeats=True):
        self.time_interval = time_interval
        self.initial_delay = initial_delay
        self.delay = delay
        self.repeats = repeats


def lock_queue(self, r):
    try:
        with self.write_lock:
            r()
    finally:
        self.write_lock.release()


def notify_domain_object_changed(listeners_to_notify, ev):
    if ev is not None and not self.is_disposed:
        for listener in listeners_to_notify:
            try:
                listener.domain_object_changed(ev)
            except Exception as exc:
                Msg.show_error(None, "Error", "Error in Domain Object listener", str(exc))
