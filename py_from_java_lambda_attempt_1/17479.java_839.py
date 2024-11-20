Here's a translation of the Java interface into equivalent Python classes:

```Python
class IAggregateReader:
    def __init__(self):
        pass

    def has_next_file(self) -> bool:
        raise NotImplementedError("has_next_file not implemented")

    def can_use_current_file_statistics(self) -> bool:
        raise NotImplementedError("can_use_current_file_statistics not implemented")

    def current_file_statistics(self) -> object:  # Replace with actual type
        raise NotImplementedError("current_file_statistics not implemented")

    def skip_current_file(self):
        pass

    def has_next_chunk(self) -> bool:
        raise NotImplementedError("has_next_chunk not implemented")

    def can_use_current_chunk_statistics(self) -> bool:
        raise NotImplementedError("can_use_current_chunk_statistics not implemented")

    def current_chunk_statistics(self) -> object:  # Replace with actual type
        raise NotImplementedError("current_chunk_statistics not implemented")

    def skip_current_chunk(self):
        pass

    def has_next_page(self) -> bool:
        raise NotImplementedError("has_next_page not implemented")

    def can_use_current_page_statistics(self) -> bool:
        raise NotImplementedError("can_use_current_page_statistics not implemented")

    def current_page_statistics(self) -> object:  # Replace with actual type
        raise NotImplementedError("current_page_statistics not implemented")

    def skip_current_page(self):
        pass

    def next_page(self) -> object:  # Replace with actual return type
        raise NotImplementedError("next_page not implemented")

    def is_ascending(self) -> bool:
        raise NotImplementedError("is_ascending not implemented")
```

Note that I've replaced the Java `throws IOException` declarations with Python's equivalent, which doesn't explicitly specify exceptions.