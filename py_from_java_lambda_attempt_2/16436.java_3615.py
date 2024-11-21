Here's the equivalent Python code:

```
class EntryUnavailableException(Exception):
    def __init__(self, index: int, boundary: int) -> None:
        super().__init__(
            f"Entry index {index} is unavailable, and the upper bound is {boundary}"
        )
```