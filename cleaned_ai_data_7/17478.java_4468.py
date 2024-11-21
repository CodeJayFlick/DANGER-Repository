import threading

class BaseManagedSeriesReader:
    def __init__(self):
        self._managed_by_pool = False
        self._has_remaining = False

    @property
    def managed_by_query_manager(self):
        return self._managed_by_pool

    @managed_by_query_manager.setter
    def set_managed_by_query_manager(self, value):
        self._managed_by_pool = value

    @property
    def has_remaining(self):
        return self._has_remaining

    @has_remaining.setter
    def set_has_remaining(self, value):
        self._has_remaining = value
