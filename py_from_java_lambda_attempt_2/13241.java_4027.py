Here is the translation of the given Java code into Python:

```Python
import io


class InnerClassesAttribute:
    def __init__(self):
        self.numberOfInnerClasses = 0
        self.inner_classes = []

    def read_from_binary_reader(self, reader: 'io.BinaryReader') -> None:
        super().__init__()
        self.numberOfInnerClasses = reader.read_next_short()
        for _ in range(self.get_number_of_inner_classes()):
            inner_class = InnerClass(reader)
            self.inner_classes.append(inner_class)

    def get_number_of_inner_classes(self) -> int:
        return self.numberOfInnerClasses & 0xffff

    def get_inner_classes(self) -> list['InnerClass']:
        return self.inner_classes


class InnerClass:
    def __init__(self, reader: 'io.BinaryReader') -> None:
        pass
```

Please note that Python does not have direct equivalent of Java's `BinaryReader` and `IOException`. The above code is a translation in the sense that it captures the same logic as the original Java code.