Here is the translation of the Java code to Python:

```Python
class ProcessedPNG:
    def __init__(self, reader):
        self.file_signature = None
        self.chunks = []
        self.total_length = 0
        self.ihdr_chunk = None

        if reader is not None:
            while True:
                chunk = PNGChunk(reader)
                if chunk.id_string == "IEND":
                    self.chunks.append(chunk)
                    self.total_length += chunk.length
                    break
                elif chunk.id_string == "ihdr":
                    self.total_length += chunk.length
                    self.ihdr_chunk = IHDRChunk(chunk)
                    self.chunks.append(chunk)
                else:
                    self.total_length += chunk.length
                    self.chunks.append(chunk)

        if reader is None:
            raise ValueError("Reader is null")

    def get_ihdr_chunk(self):
        return self.ihdr_chunk

    def get_total_length(self):
        return self.total_length

    def get_file_signature(self):
        return self.file_signature

    def get_chunks(self):
        return self.chunks


class PNGChunk:
    def __init__(self, reader):
        pass  # This class is not implemented in the original Java code. It seems to be a placeholder.


class IHDRChunk(PNGChunk):
    def __init__(self, chunk):
        super().__init__()
        self.length = chunk.length
        self.id_string = "ihdr"


def main():
    reader = BinaryReader()  # This class is not implemented in the original Java code. It seems to be a placeholder.
    processed_png = ProcessedPNG(reader)
    print(processed_png.get_ihdr_chunk())
    print(processed_png.get_total_length())
    print(processed_png.get_file_signature())
    for chunk in processed_png.get_chunks():
        print(chunk.id_string)


if __name__ == "__main__":
    main()
```

Please note that the `BinaryReader` class and some other classes are not implemented here as they were placeholders in the original Java code.