Here is the translation of the given Java code into Python:

```Python
class ChunkModel:
    def __init__(self):
        self.chunks = []
        self.selected_byte_start = None
        self.selected_byte_end = None
        self.NUM_LINES = 250
        self.MAX_VISIBLE_CHUNKS = 3

    def add(self, chunk):
        self.chunks.append(chunk)

    def add_at_index(self, index, chunk):
        self.chunks.insert(index, chunk)

    def remove_at_index(self, index):
        if 0 <= index < len(self.chunks):
            return self.chunks.pop(index)
        return None

    def clear(self):
        self.chunks.clear()

    @property
    def size(self):
        return len(self.chunks)

    def get_chunk_at_index(self, index):
        if 0 <= index < len(self.chunks):
            return self.chunks[index]
        return None

    def __iter__(self):
        return iter(self.chunks)

    @property
    def num_chunks(self):
        return len(self.chunks)

    def file_position_for_row(self, row):
        total_lines = 0
        for chunk in self:
            if row < chunk.lines_in_chunk + total_lines:
                my_row = chunk.lines_in_chunk - ((chunk.lines_in_chunk + total_lines) - row)
                byte_range = chunk.row_to_file_position_map.get(my_row)
                return byte_range
            total_lines += chunk.lines_in_chunk

        return None

    def row_for_byte_pos(self, selected_byte):
        total_lines = 0
        for chunk in self:
            if selected_byte >= chunk.start and selected_byte <= chunk.end:	
                for entry in chunk.row_to_file_position_map.items():
                    key, value = entry
                    if selected_byte >= value[1].start and selected_byte <= value[1].end:
                        return key + total_lines

            total_lines += chunk.lines_in_chunk

        return -1


class Chunk:
    def __init__(self):
        self.start = None
        self.end = None
        self.lines_in_chunk = 0
        self.row_to_file_position_map = {}

```

Note that Python does not have direct equivalents for Java's `List` and `Iterator`, so we use a list (`chunks`) and iterate over it using the built-in `iter()` function. Also, Python has no concept of "protected" or "public" access modifiers like Java; instead, you can control access to attributes by making them private (prefixing with `_`) and providing getter/setter methods for public access.