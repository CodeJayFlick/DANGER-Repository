import threading
from queue import Queue
from typing import List

class FileSystemEventManager:
    def __init__(self, enable_asynchronous_dispatching: bool):
        self.listeners = []
        self.event_queue = Queue()
        self.disposed = False
        if enable_asynchronous_dispatching:
            thread = threading.Thread(target=self.process_events)
            thread.start()

    def dispose(self):
        self.disposed = True
        if hasattr(self, 'thread'):
            self.thread.interrupt()

    def add_listener(self, listener: callable) -> None:
        self.listeners.append(listener)

    def remove_listener(self, listener: callable) -> None:
        try:
            self.listeners.remove(listener)
        except ValueError:
            pass

    def item_moved(self, parent_path: str, name: str, new_parent_path: str, new_name: str):
        if not self.disposed:
            event = ItemMovedEvent(parent_path, name, new_parent_path, new_name)
            self.event_queue.put(event)

    def item_renamed(self, parent_path: str, name: str, new_name: str):
        if not self.disposed:
            event = ItemRenamedEvent(parent_path, name, new_name)
            self.event_queue.put(event)

    # ... (similar methods for other events)

    def process_events(self) -> None:
        while not self.disposed:
            try:
                event = self.event_queue.get()
                if isinstance(event, MarkerEvent):
                    break
                for listener in self.listeners:
                    listener(event)
            except InterruptedException:
                pass

class FileSystemEvent:
    parent_path: str
    name: str
    new_parent_path: str
    new_name: str

    def __init__(self, parent_path: str, name: str, new_parent_path: str = None, new_name: str = None):
        self.parent_path = parent_path
        self.name = name
        self.new_parent_path = new_parent_path
        self.new_name = new_name

    def process(self, listeners: List[callable]) -> None:
        for listener in listeners:
            listener(self)

class ItemMovedEvent(FileSystemEvent):
    pass

class ItemRenamedEvent(FileSystemEvent):
    pass

# ... (similar classes for other events)

class MarkerEvent(FileSystemEvent):
    latch = threading.CountDownLatch(1)

    def process(self, listeners: List[callable]) -> None:
        self.latch.count_down()

    def wait_for_event(self, timeout: float) -> bool:
        return self.latch.await(timeout)
