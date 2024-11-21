Here is the equivalent Python code:

```Python
class FakedTsFileResource:
    def __init__(self, ts_file_size: int, name: str):
        self.ts_file_size = ts_file_size
        self.fake_ts_file_name = name
        self.closed = True
        self.is_merging = False

    def set_ts_file_size(self, ts_file_size: int) -> None:
        self.ts_file_size = ts_file_size

    @property
    def ts_file_size(self) -> int:
        return self._ts_file_size

    def __str__(self) -> str:
        return f"{self.ts_file_size},{self.closed},{self.is_merging}"

    def get_ts_file(self) -> 'os.path.join':
        return os.path.join(self.fake_ts_file_name)

# Example usage
faked_resource = FakedTsFileResource(100, "example")
print(faked_resource)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of a class extending another. In this translation, I've kept the same structure and naming conventions as in the original code to make it easier to understand how each part corresponds to its counterpart in the other language.