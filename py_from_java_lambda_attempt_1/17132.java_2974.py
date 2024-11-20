Here is the translation of the Java interface `ILastCacheContainer` to a Python class:
```python
class ILastCacheContainer:
    def __init__(self):
        pass  # no equivalent in Python, but included for consistency with Java

    def init(self, size: int) -> None:
        """Initialize LastCache Value list"""
        pass  # implementation left out, as it depends on the specific use case

    def get_cached_last(self) -> 'TimeValuePair':
        """Get last cache of monad time series"""
        raise NotImplementedError("Not implemented")

    def get_cached_last(self, index: int) -> 'TimeValuePair':
        """Get last cache of vector time series at given index"""
        raise NotImplementedError("Not implemented")

    def update_cached_last(
            self,
            time_value_pair: 'TimeValuePair',
            high_priority_update: bool,
            latest_flushed_time: int
    ) -> None:
        """
        Update last point cache

        :param time_value_pair: Last point to be cached
        :param high_priority_update: Whether it's a high priority update
        :param latest_flushed_time: Latest flushed time
        """
        pass  # implementation left out, as it depends on the specific use case

    def update_cached_last(
            self,
            index: int,
            time_value_pair: 'TimeValuePair',
            high_priority_update: bool,
            latest_flushed_time: int
    ) -> None:
        """Update last cache for vector time series at given index"""
        pass  # implementation left out, as it depends on the specific use case

    def reset_last_cache(self) -> None:
        """
        Reset all LastCache data of one timeseries (monad or vector)
        """
        raise NotImplementedError("Not implemented")

    def reset_last_cache(self, index: int) -> None:
        """Reset last cache of vector's subsensor at given index"""
        raise NotImplementedError("Not implemented")

    def is_empty(self) -> bool:
        """Check if the entry contains LastCache Value."""
        return False  # default implementation
```
Note that I've used Python's type hints to indicate the expected types for method parameters and return values. Additionally, I've left out any specific implementations of methods as they depend on the specific use case.

In Python, we don't have a direct equivalent to Java interfaces, but we can achieve similar functionality using abstract base classes (ABCs) or protocols. However, since this code is primarily focused on providing an interface for other parts of your system to interact with, I've chosen to implement it as a regular class in Python.