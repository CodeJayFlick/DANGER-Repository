Here is the translation of the Java code into Python:

```Python
class ChunkReader:
    def __init__(self, chunk: 'Chunk', filter: 'Filter') -> None:
        self.filter = filter
        self.chunk_data_buffer = chunk.data
        self.delete_interval_list = chunk.delete_intervals
        self.chunk_header = chunk.header
        self.un_compressor = get_un_compressor(chunk_header.compression_type)
        if chunk.is_from_old_file():
            self.init_all_page_readers_v2()
        else:
            self.init_all_page_readers(chunk.statistic)

    def init_all_page_readers(self, statistic: 'Statistics') -> None:
        while self.chunk_data_buffer.remaining() > 0:
            page_header = deserialize_page_header(self.chunk_data_buffer)
            if page_satisfied(page_header):
                self.page_reader_list.append(construct_page_reader_for_next_page(page_header))
            else:
                skip_bytes_in_stream_by_length(page_header.compressed_size)

    def has_next_satisfied_page(self) -> bool:
        return not self.page_reader_list.empty()

    def next_page_data(self) -> 'BatchData':
        if self.page_reader_list.empty():
            raise IOException("No more page")
        return self.page_reader_list.pop(0).get_all_satisfied_page_data()

    def skip_bytes_in_stream_by_length(self, length: int) -> None:
        self.chunk_data_buffer.position(self.chunk_data_buffer.position() + length)

    def page_satisfied(self, page_header: 'PageHeader') -> bool:
        if self.delete_interval_list is not None:
            for range in self.delete_interval_list:
                if range.contains(page_header.start_time, page_header.end_time):
                    return False
                if range.overlaps(TimeRange(page_header.start_time, page_header.end_time)):
                    page_header.set_modified(True)
        return filter.satisfy(page_header.statistic) if filter is not None else True

    def construct_page_reader_for_next_page(self, page_header: 'PageHeader') -> 'PageReader':
        compressed_page_body_length = page_header.compressed_size
        compressed_page_body = bytearray(compressed_page_body_length)

        if compressed_page_body_length > self.chunk_data_buffer.remaining():
            raise IOException(f"Doesn't have a complete page body. Expected {compressed_page_body_length}, Actual {self.chunk_data_buffer.remaining()}")

        self.chunk_data_buffer.get(compressed_page_body)
        value_decoder = get_decoder_by_type(page_header.data_type, chunk_header.encoding_type)
        uncompressed_page_data = bytearray(page_header.uncompressed_size)
        try:
            un_compressor.uncompress(
                compressed_page_body,
                0,
                compressed_page_body_length,
                uncompressed_page_data,
                0
            )
        except Exception as e:
            raise IOException(f"Uncompress error! Uncompress size: {page_header.uncompressed_size}, Compressed size: {page_header.compressed_size}, Page header: {page_header}, {e}")

        page_data = memoryview(uncompressed_page_data)
        reader = PageReader(
            page_header,
            page_data,
            chunk_header.data_type,
            value_decoder,
            time_decoder,
            filter
        )
        reader.set_delete_interval_list(self.delete_interval_list)
        return reader

    def close(self) -> None:
        pass

    @property
    def chunk_header(self):
        return self.chunk_header

    def load_page_reader_list(self) -> list['IPageReader']:
        return self.page_reader_list


def get_un_compressor(compression_type: int) -> 'IUnCompressor':
    # implement this method to get the uncompressor based on compression type
    pass


class PageHeader:
    @classmethod
    def deserialize_from(cls, buffer: memoryview):
        # implement this method to deserialize a page header from the given buffer
        pass

def construct_page_reader_for_next_page_v2(self, page_header: 'PageHeader') -> 'PageReader':
    compressed_page_body_length = page_header.compressed_size
    compressed_page_body = bytearray(compressed_page_body_length)

    if compressed_page_body_length > self.chunk_data_buffer.remaining():
        raise IOException(f"Doesn't have a complete page body. Expected {compressed_page_body_length}, Actual {self.chunk_data_buffer.remaining()}")

    self.chunk_data_buffer.get(compressed_page_body)
    value_decoder = get_decoder_by_type(page_header.data_type, chunk_header.encoding_type)
    uncompressed_page_data = bytearray(page_header.uncompressed_size)
    un_compressor.uncompress(
        compressed_page_body,
        0,
        compressed_page_body_length,
        uncompressed_page_data,
        0
    )
    page_data = memoryview(uncompressed_page_data)
    reader = PageReaderV2(
        page_header,
        page_data,
        chunk_header.data_type,
        value_decoder,
        time_decoder,
        filter
    )
    reader.set_delete_interval_list(self.delete_interval_list)
    return reader

def get_decoder_by_type(data_type: int, encoding_type: int) -> 'Decoder':
    # implement this method to get the decoder based on data type and encoding type
    pass


class PageReaderV2:
    def __init__(self):
        pass

    @property
    def delete_interval_list(self):
        return self.delete_interval_list
```

Note that I've used Python's `bytearray` for byte arrays, `memoryview` to represent buffers as memory views, and the `@classmethod` decorator to define class methods.