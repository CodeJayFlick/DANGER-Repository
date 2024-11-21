Here is the equivalent Python code:

```Python
class LimitedByteBuffer:
    def __init__(self, initial, amax):
        self.value = bytearray(initial)
        self.count = 0
        self.absmax = amax

    def append(self, b: bytes) -> None:
        new_count = self.count + 1
        if new_count > len(self.value):
            if new_count > self.absmax:
                raise ValueError(f"Decompiler results exceeded payload limit of {self.absmax // (1024 * 1024)} MBytes")
            new_capacity = len(self.value) * 2
            if new_capacity < 0:
                new_capacity = max(new_capacity, self.absmax)
            self.value = bytearray(self.value[:new_count] + [b])
        else:
            self.value[self.count:] = [b]
        self.count += 1

    def get_stream(self) -> bytes:
        return self.value[:self.count]

    def __str__(self):
        return str(self.value[:self.count].decode('utf-8'))
```

Note that Python does not have a direct equivalent to Java's `ByteArrayInputStream`. Instead, you can simply return the buffer as is. Also, in Python, we don't need to explicitly throw exceptions like `IOException` or check for array bounds using `if newCount > value.length`, because these operations are handled by the language itself.