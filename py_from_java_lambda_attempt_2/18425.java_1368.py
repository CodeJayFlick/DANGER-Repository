Here is the translation of the Java code to Python:

```Python
import os
from typing import List, Map, Tuple

class TsFileSequenceReader:
    def __init__(self, file_path: str):
        self.file_path = file_path
        # Initialize other attributes as needed

    def read_marker(self) -> int:
        # Implement the logic to read a marker from the file
        pass

    def read_chunk_header(self, marker: int) -> Tuple[int, int]:
        # Implement the logic to read a chunk header based on the given marker
        pass

    def read_page_header(self, data_type: str, is_only_one_page: bool) -> None:
        # Implement the logic to read a page header
        pass

    def read_page(self, page_header: int, compression_type: str) -> bytes:
        # Implement the logic to read a page based on the given page header and compression type
        pass

    def close(self):
        # Close any open resources as needed
        pass


class ReadOnlyTsFile:
    def __init__(self, file_reader: TsFileSequenceReader):
        self.file_reader = file_reader

    def close(self):
        # Close any open resources as needed
        pass


def test_read_ts_file_sequentially() -> None:
    reader = TsFileSequenceReader(FILE_PATH)
    position = TSFileConfig.MAGIC_STRING.encode().length + 1
    device_chunk_group_metadata_offsets: Map[str, List[Tuple[int, int]]] = {}

    start_offset = reader.position()
    marker = reader.read_marker()

    while marker != MetaMarker.SEPARATOR:
        if marker in [MetaMarker.CHUNK_HEADER, MetaMarker.ONLY_ONE_PAGE_CHUNK_HEADER]:
            header = reader.read_chunk_header(marker)
            data_size = header.get_data_size()

            while data_size > 0:
                page_header = reader.read_page_header(header.data_type(), header.chunk_type() == MetaMarker.CHUNK_HEADER)
                page_data = reader.read_page(page_header, header.compression_type())
                data_size -= page_header.serialized_page_size

        elif marker == MetaMarker.CHUNK_GROUP_HEADER:
            chunk_group_header = reader.read_chunk_group_header()
            end_offset = reader.position()
            pair = (start_offset, end_offset)
            device_chunk_group_metadata_offsets.setdefault(chunk_group_header.device_id(), []).append(pair)
            start_offset = end_offset
        else:
            handle_unexpected_marker(marker)

    reader.close()


def test_read_chunk_metadata_in_device() -> None:
    reader = TsFileSequenceReader(FILE_PATH)

    # Test for exist device "d2"
    chunk_metadata_map: Map[str, List[ChunkMetadata]] = reader.read_chunk_metadata_in_device("d2")
    res = [20, 75, 100, 13]

    assert len(chunk_metadata_map) == 4
    for i in range(len(chunk_metadata_map)):
        id = i + 1
        metadata_list = chunk_metadata_map["s" + str(id)]
        num_of_points = sum(metadata.num_of_points() for metadata in metadata_list)
        assert res[i] == num_of_points

    # Test for non-exist device "d3"
    assert reader.read_chunk_metadata_in_device("d3").empty
    reader.close()


if __name__ == "__main__":
    FILE_PATH = os.path.join(os.getcwd(), 'your_file_path.txt')
    test_read_ts_file_sequentially()
    test_read_chunk_metadata_in_device()

```

Note that this translation is not a direct conversion, but rather an equivalent implementation in Python. Some parts of the code may need to be adjusted based on your specific requirements and constraints.