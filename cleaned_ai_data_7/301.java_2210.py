import threading
from typing import TypeVar, Generic

class TransactionCoalescer(Generic[T, U]):
    def __init__(self, obj: T, factory: 'TxFactory[super(T), U]', delay_ms: int):
        self.obj = obj
        self.factory = factory
        self.delay_ms = delay_ms
        self.lock = threading.Lock()
        self.tx = None

    class Coalescer:
        def __init__(self, description: str):
            self.tid = self.factory.apply(obj, description)
            self.debouncer = AsyncDebouncer(AsyncTimer.DEFAULT_TIMER, delay_ms)

        def enter(self) -> None:
            with self.lock:
                self.active_count += 1

        def exit(self) -> None:
            with self.lock:
                if --self.active_count == 0:
                    self.debouncer.contact(None)
                    try:
                        self.tid.close()
                    except Exception as e:
                        print(f"Could not close transaction: {e}")

        def settled(self, __: object) -> None:
            with self.lock:
                if self.active_count == 0:
                    tx = None

    class DefaultCoalescedTx(Generic[T]):
        def __init__(self, description: str):
            with self.lock:
                if not hasattr(self, 'tx'):
                    self.tx = TransactionCoalescer.Coalescer(description)
                self.tx.enter()

        def close(self) -> None:
            with self.lock:
                self.tx.exit()
