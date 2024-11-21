Here is the translation of the given Java interface into a Python class:

```Python
class TraceBookmarkRegisterSpace:
    def get_thread(self):
        pass  # This method should be implemented in subclass

    def add_bookmark(self, lifespan: range, register_address: int, 
                     bookmark_type: str, category: str, comment: str) -> 'TraceBookmark':
        return self.add_bookmark(lifespan, register_address, bookmark_type, category, comment)

    def get_bookmarks_enclosed(self, lifespan: range, register_range: tuple[int]) -> iter:
        pass  # This method should be implemented in subclass

    def get_bookmarks_intersecting(self, lifespan: range, register_range: tuple[int]) -> iter:
        pass  # This method should be implemented in subclass
```

Note that the Python code does not have direct equivalent of Java's interface. Instead, we define a class with methods which are similar to those defined in the original Java interface. The `get_thread` and other methods do not have any implementation as they were abstract in the original Java interface.

Also note that I used type hints for method parameters and return types, but Python does not enforce these at runtime like some statically-typed languages might.