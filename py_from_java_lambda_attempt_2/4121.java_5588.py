Here is the equivalent Python code:

```
class EntropyChunkSize:
    SMALL = ("256 Bytes", 256)
    MEDIUM = ("512 Bytes", 512)
    LARGE = ("1024 Bytes", 1024)

    def __init__(self, label, chunksize):
        self.label = label
        self.chunksize = chunksize

    def __str__(self):
        return self.label

    @property
    def get_chunk_size(self):
        return self.chunksize


# Example usage:
chunk_sizes = [EntropyChunkSize(*s) for s in EntropyChunkSize.__dict__.values()]
for size in chunk_sizes:
    print(f"Label: {size}, Chunk Size: {size.get_chunk_size}")
```

Note that Python does not have an exact equivalent to Java's enum type. Instead, we define a class `EntropyChunkSize` with static attributes and methods. The `__init__`, `__str__`, and `get_chunk_size` methods are similar to their Java counterparts.