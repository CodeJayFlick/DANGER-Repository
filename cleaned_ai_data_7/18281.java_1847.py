class VectorChunkReader:
    def __init__(self, time_chunk: 'Chunk', value_chunks: List['Chunk'], filter):
        self.filter = filter
        self.time_chunk_data_buffer = time_chunk.data
        self.value_delete_interval_list = []
        self.time_chunk_header = time_chunk.header
        self.un_compressor = IUnCompressor.get_un_compressor(time_chunk_header.compression_type)
        value_chunk_statistics_list = [chunk.chunk_statistic for chunk in value_chunks]
        for chunk in value_chunks:
            self.value_chunk_header_list.append(chunk.header)
            self.value_chunk_data_buffer_list.append(chunk.data)
            self.value_delete_interval_list.append(chunk.delete_interval_list())
        self.init_all_page_readers(time_chunk.chunk_statistic, value_chunk_statistics_list)

    def init_all_page_readers(self, time_chunk_statistics: 'Statistics', value_chunk_statistics_list):
        while self.time_chunk_data_buffer.remaining() > 0:
            if (self.time_chunk_header.chunk_type & 0x3F) == MetaMarker.ONLY_ONE_PAGE_CHUNK_HEADER:
                page_headers = [PageHeader.deserialize_from(self.time_chunk_data_buffer, time_chunk_statistics)]
                for i in range(len(value_chunks)):
                    value_page_headers.append(PageHeader.deserialize_from(
                        self.value_chunk_data_buffer_list[i], value_chunk_statistics_list[i]))
            else:  # this chunk has more than one page
                page_header = PageHeader.deserialize_from(self.time_chunk_data_buffer, time_chunk_header.data_type)
                for i in range(len(value_chunks)):
                    value_page_headers.append(PageHeader.deserialize_from(
                        self.value_chunk_data_buffer_list[i], value_chunk_header_list[i].data_type))
            if self.page_satisfied(page_header):
                page_reader = construct_page_reader_for_next_page(page_header, value_page_headers)
                self.page_reader_list.append(page_reader)
            else:
                skip_bytes_in_stream_by_length(page_header, value_page_headers)

    def page_satisfied(self, page_header: 'PageHeader'):
        return filter is None or filter.satisfy(page_header.statistics)

    # used for value page filter
    def page_satisfied(self, page_header: 'PageHeader', delete_interval_list):
        if delete_interval_list:
            for range in delete_interval_list:
                if range.contains(page_header.start_time, page_header.end_time):
                    return False
                if range.overlaps(TimeRange(page_header.start_time, page_header.end_time)):
                    page_header.modified = True
            return filter is None or filter.satisfy(page_header.statistics)
        else:
            return self.page_satisfied(page_header)

    def construct_page_reader_for_next_page(self, time_page_header: 'PageHeader', value_page_headers):
        if not hasattr(time_page_info, '__dict__'):
            time_page_info = PageInfo()
        for i in range(len(value_chunks)):
            page_info = PageInfo()  # new
            get_page_info(page_header=value_page_headers[i], chunk_buffer=self.value_chunk_data_buffer_list[i],
                          chunk_header=value_chunk_header_list[i], page_info=page_info)
            value_page_reader_list.append(PageHeader.deserialize_from(
                self.value_chunk_data_buffer_list[i], value_chunk_statistics_list[i]))
        return VectorPageReader(time_page_header, time_page_info.page_data,
                                 Decoder.get_decoder_by_type(value_chunk_header_list[0].encoding_type,
                                                           value_chunk_header_list[0].data_type),
                                 value_page_reader_list, filter)

    def get_page_info(self, page_header: 'PageHeader', chunk_buffer: ByteBuffer, chunk_header: ChunkHeader, page_info):
        if not hasattr(page_info, '__dict__'):
            page_info = PageInfo()
        page_info.page_header = page_header
        page_info.data_type = chunk_header.data_type
        compressed_page_body_length = page_header.compressed_size
        uncompressed_page_data = bytearray(compressed_page_body_length)
        try:
            un_compressor.un_compress(
                bytes(page_header), 0, compressed_page_body_length,
                uncompressed_page_data, 0)
        except Exception as e:
            raise IOException("Uncompress error! Uncompressed size: " + str(uncompressed_page_data) +
                               " Compressed size: " + str(compressed_page_body_length) +
                               " Page header: " + page_header +
                               e.message)

    def skip_bytes_in_stream_by_length(self, time_page_header: 'PageHeader', value_page_headers):
        self.time_chunk_data_buffer.position(
            self.time_chunk_data_buffer.position() + time_page_header.compressed_size)
        for i in range(len(value_chunks)):
            self.value_chunk_data_buffer_list[i].position(
                self.value_chunk_data_buffer_list[i].position() +
                value_page_headers[i].compressed_size)

    def __next_satisfied_page(self):
        return not self.page_reader_list.empty()

    def next_page_data(self):
        if self.page_reader_list.empty():
            raise IOException("No more page")
        else:
            return self.page_reader_list.pop(0).get_all_satisfied_page_data()

    def close(self):
        pass

class PageInfo:
    def __init__(self, **kwargs):
        for key in kwargs.keys():
            setattr(self, key, kwargs[key])

def main():
    # Your code here
if __name__ == "__main__":
    main()
