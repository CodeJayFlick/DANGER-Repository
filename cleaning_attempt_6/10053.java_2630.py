import threading
from typing import Any

class SpyTextFilter:
    def __init__(self, text_filter: str, transformer: callable, recorder: 'SpyEventRecorder') -> None:
        self.text_filter = text_filter
        self.transformer = transformer
        self.recorder = recorder
        self.has_filtered = False
        self.filter_count = 0

    def accepts_row(self, row_object: Any) -> bool:
        with threading.Lock():
            if not self.has_filtered:
                self.recorder.record("Model - filter started")
            self.has_filtered = True
            self.filter_count += 1
            return super().accepts_row(row_object)

    @property
    def has_filtered(self) -> bool:
        return self._has_filtered

    @has_filtered.setter
    def has_filtered(self, value: bool) -> None:
        self._has_filtered = value

    @property
    def filter_count(self) -> int:
        return self._filter_count

    @filter_count.setter
    def filter_count(self, value: int) -> None:
        self._filter_count = value

    def reset(self) -> None:
        with threading.Lock():
            self.recorder.record("Test - filter spy reset")
            self.has_filtered = False
            self.filter_count = 0

    def dump_events(self) -> None:
        self.recorder.dump_events()
