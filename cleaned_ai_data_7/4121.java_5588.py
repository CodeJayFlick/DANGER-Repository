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
