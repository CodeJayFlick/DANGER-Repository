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
