Here is the translation of the Java code to Python:
```
import io

class CachedUnseqResourceMergeReader:
    def __init__(self, chunks: list[io.Chunk], data_type):
        super().__init__(data_type)
        priority_value = 1
        for chunk in chunks:
            reader = ChunkReader(chunk, None)  # Note: `None` is used as the second argument here
            self.add_reader(ChunkDataIterator(reader), priority_value + 1)

class ChunkReader:
    def __init__(self, chunk: io.Chunk, _):
        pass

class ChunkDataIterator:
    def __init__(self, reader: ChunkReader):
        pass

# Note: The `TSDataType` enum is not directly translatable to Python,
# so I left it out. You may need to create a separate class or use an existing one
# that represents the equivalent concept in Python.
```
Note that this translation assumes that:

* `io.Chunk` and its related classes (`ChunkReader`, etc.) are part of the same package as the original Java code, and can be used directly in Python. If not, you may need to create separate Python classes or use existing ones that provide similar functionality.
* The `TSDataType` enum is not a direct equivalent in Python, so I left it out. You will likely need to create a separate class or use an existing one that represents the equivalent concept in Python.

Also note that this translation does not include any error handling for exceptions like `IOException`, which are typically handled using try-except blocks in Python.