class TsFileMetadata:
    def __init__(self):
        self.bloom_filter = None
        self.metadata_index = None
        self.meta_offset = 0

    @classmethod
    def deserialize_from(cls, buffer):
        file_metadata = cls()
        
        # metadataIndex
        file_metadata.metadata_index = MetadataIndexNode.deserialize_from(buffer)

        # metaOffset
        file_metadata.set_meta_offset(int.from_bytes(buffer.read(8), 'big'))

        if buffer.tell() < len(buffer):
            bytes_length = int.from_bytes(buffer.read(4), 'big')
            filter_size = int.from_bytes(buffer.read(4), 'big')
            hash_function_size = int.from_bytes(buffer.read(4), 'big')

            file_metadata.bloom_filter = BloomFilter.build_bloom_filter(bytes_length, filter_size, hash_function_size)

        return file_metadata

    def get_bloom_filter(self):
        return self.bloom_filter

    def set_bloom_filter(self, bloom_filter):
        self.bloom_filter = bloom_filter

    def serialize_to(self, output_stream):
        byte_len = 0
        
        if self.metadata_index is not None:
            byte_len += self.metadata_index.serialize_to(output_stream)
        else:
            output_stream.write(b'\x00')

        output_stream.write(int.to_bytes(self.meta_offset, 'big', False))

    def serialize_bloom_filter(self, output_stream, paths):
        byte_len = 0
        filter = build_bloom_filter(paths)

        bytes_length = len(filter.serialize())
        output_stream.write(int.to_bytes(bytes_length, 'big', False))
        output_stream.write(filter.serialize())

        byte_len += len(filter.serialize()) + 12

    def get_meta_offset(self):
        return self.meta_offset

    def set_meta_offset(self, meta_offset):
        self.meta_offset = meta_offset

    def get_metadata_index(self):
        return self.metadata_index

    def set_metadata_index(self, metadata_index):
        self.metadata_index = metadata_index


class MetadataIndexNode:
    @classmethod
    def deserialize_from(cls, buffer):
        # TO DO: implement deserialization of MetadataIndexNode from a ByteBuffer in Python
        pass


def build_bloom_filter(paths):
    filter = BloomFilter.get_empty_bloom_filter(TSFileDescriptor().get_config().get_bloom_filter_error_rate(), len(paths))
    
    for path in paths:
        filter.add(path)

    return filter

class TSFileDescriptor:
    @classmethod
    def get_instance(cls):
        # TO DO: implement getting an instance of TSFileDescriptor in Python
        pass
    
    @classmethod
    def get_config(cls):
        # TO DO: implement getting the config from a TSFileDescriptor in Python
        pass


# Usage example:

ts_file_metadata = TsFileMetadata()
buffer = bytearray(1024)
output_stream = open('file.bin', 'wb')

ts_file_metadata.deserialize_from(buffer)

ts_file_metadata.serialize_to(output_stream)

paths = [Path('/path1'), Path('/path2')]
ts_file_metadata.serialize_bloom_filter(output_stream, paths)

output_stream.close()

