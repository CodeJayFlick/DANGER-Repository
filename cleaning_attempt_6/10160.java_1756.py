from concurrent.futures import Future as _Future, ThreadPoolExecutor
import threading


class QResult:
    def __init__(self, item: 'I', future_task_monitor: 'FutureTaskMonitor'):
        self.item = item
        self.future_task_monitor = future_task_monitor

    @property
    def result(self):
        return None  # This should be implemented based on the actual use case


class FutureTaskMonitor:
    def __init__(self, queue: 'ConcurrentQ', callable_, item: 'I', id_):
        super().__init__(callable_)
        self.queue = queue
        self.id = id_
        self.item = item

    @property
    def item(self) -> 'I':
        return self._item

    @item.setter
    def item(self, value: 'I'):
        self._item = value

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    def run(self) -> None:
        super().run()
        result = QResult(self.item, self)
        self.queue.item_processed(self, result)

    def set_maximum(self, max: int) -> None:
        self.max_progress = max
        self.queue.max_progress_changed(self.id, self.item, max)

    @property
    def current_progress(self):
        return self._current_progress

    @current_progress.setter
    def current_progress(self, value: int):
        self._current_progress = value
        self.queue.progress_changed(self.id, self.item, value)

    @property
    def max_progress(self) -> int:
        return self._max_progress

    @max_progress.setter
    def max_progress(self, value: int):
        self._max_progress = value
        self.queue.max_progress_changed(self.id, self.item, value)

    def increment_progress(self, amount: int) -> None:
        self.current_progress += amount
        self.queue.progress_changed(self.id, self.item, self.current_progress)

    @property
    def last_message(self):
        return self._last_message

    @last_message.setter
    def last_message(self, value: str):
        self._last_message = value
        self.queue.progress_message_changed(self.id, self.item, value)

    def check_cancelled(self) -> None:
        if self.is_cancelled():
            raise CancelledException()

    def set_progress(self, progress: int) -> None:
        self.current_progress = progress
        self.queue.progress_changed(self.id, self.item, progress)

    @property
    def is_indeterminate(self):
        return self._is_indeterminate

    @is_indeterminate.setter
    def is_indeterminate(self, value: bool):
        if not isinstance(value, bool):
            raise TypeError("Value must be a boolean")
        self._is_indeterminate = value
        self.queue.progress_mode_changed(self.id, self.item, value)

    def initialize(self, max_progress: int) -> None:
        self.current_progress = 0
        self.max_progress = max_progress
        self.queue.max_progress_changed(self.id, self.item, max_progress)
        self.queue.progress_changed(self.id, self.item, self.current_progress)


class CancelledException(Exception):
    pass


class ChainedCancelledListener:
    def __init__(self, listener1: 'CancelledListener', listener2: 'CancelledListener'):
        self.listener1 = listener1
        self.listener2 = listener2

    @property
    def listener1(self) -> 'CancelledListener':
        return self._listener1

    @listener1.setter
    def listener1(self, value):
        if not isinstance(value, CancelledListener):
            raise TypeError("Value must be a CancelledListener")
        self._listener1 = value

    @property
    def listener2(self) -> 'CancelledListener':
        return self._listener2

    @listener2.setter
    def listener2(self, value: 'CancelledListener'):
        if not isinstance(value, CancelledListener):
            raise TypeError("Value must be a CancelledListener")
        self._listener2 = value

    def remove_listener(self, listener) -> 'ChainedCancelledListener':
        if self.listener1 == listener:
            return ChainedCancelledListener(None, self.listener2)
        elif self.listener2 == listener:
            return ChainedCancelledListener(self.listener1, None)

        new_listener1 = self.listener1
        while isinstance(new_listener1, ChainedCancelledListener):
            new_listener1 = new_listener1.listener1

        if new_listener1 != listener and isinstance(new_listener1, CancelledListener):
            new_listener2 = self.listener2
            while isinstance(new_listener2, ChainedCancelledListener):
                new_listener2 = new_listener2.listener2

            return ChainedCancelledListener(None, None)

        return self


    def cancelled(self) -> None:
        if self.listener1 is not None:
            self.listener1.cancelled()
        if self.listener2 is not None:
            self.listener2.cancelled()


class CancelledListener:
    pass
