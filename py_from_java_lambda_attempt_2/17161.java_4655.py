Here is the translation of the Java code to Python:
```
class CollectorTraverser(T):
    def __init__(self, start_node: 'IMNode', path: 'PartialPath') -> None:
        super().__init__(start_node, path)

    def __init__(self, start_node: 'IMNode', path: 'PartialPath', limit: int, offset: int) -> None:
        super().__init__(start_node, path)
        self.limit = limit
        self.offset = offset
        if limit != 0 or offset != 0:
            self.has_limit = True

    def traverse(self, node: 'IMNode', idx: int, level: int) -> None:
        if self.has_limit and self.count == self.limit:
            return
        super().traverse(node, idx, level)

    @property
    def result_set(self):
        return self.result_set

    @result_set.setter
    def result_set(self, value: T):
        self.result_set = value

    @property
    def cur_offset(self) -> int:
        return self.cur_offset

    @cur_offset.setter
    def cur_offset(self, value: int):
        self.cur_offset = value

    def set_limit(self, limit: int) -> None:
        self.limit = limit
        if limit != 0:
            self.has_limit = True

    def set_offset(self, offset: int) -> None:
        self.offset = offset
        if offset != 0:
            self.has_limit = True
```
Note that I used the `T` type hint to indicate that this is a generic class. In Python, you don't need to specify the type of variables or method parameters like you do in Java.

Also, I replaced the `@Override` annotation with nothing, since Python doesn't have an equivalent concept. The `super()` function is used to call the parent class's constructor or method.

The rest of the code should be self-explanatory!