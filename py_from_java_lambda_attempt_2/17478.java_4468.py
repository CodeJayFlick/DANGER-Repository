Here is the translation of the Java code to Python:
```
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
```
Note that I used Python's property decorator to create getter and setter methods for the `managed_by_query_manager` and `has_remaining` attributes. This is equivalent to Java's `@Override` method overriding.

Also, since Python does not have a built-in concept of "volatile" like Java does, I did not include any specific handling for it in this translation.