Here is the equivalent Python code:

```Python
class GdbModuleSection:
    def __init__(self, name: str, vma_start: int, vma_end: int, file_offset: int, attrs: list):
        self.name = name
        self.vma_start = vma_start
        self.vma_end = vma_end
        self.file_offset = file_offset
        self.attrs = attrs[:]

    def get_name(self) -> str:
        return self.name

    def get_vma_start(self) -> int:
        return self.vma_start

    def get_vma_end(self) -> int:
        return self.vma_end

    def get_file_offset(self) -> int:
        return self.file_offset

    def get_attributes(self) -> list:
        return self.attrs
```

Note that Python does not have direct equivalents to Java's `protected` access modifier or the concept of a "package". In Python, you can use private variables (prefixed with `_`) and public methods as needed.