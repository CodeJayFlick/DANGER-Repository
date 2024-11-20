Here is the translation of the Java code to Python:

```Python
class CrossSpaceMergeResource:
    def __init__(self, seq_files: list, unseq_files: list):
        self.seq_files = [file for file in seq_files if self.filter_resource(file)]
        self.unseq_files = [file for file in unseq_files if self.filter_resource(file)]

    @staticmethod
    def filter_resource(resource) -> bool:
        return resource.exists() and not resource.is_deleted() and (not resource.is_closed() or resource.still_lives()) and not resource.is_merging()

    def clear(self):
        for reader in self.file_reader_cache.values():
            reader.close()
        for writer in self.file_writer_cache.values():
            writer.close()
        self.file_reader_cache.clear()
        self.file_writer_cache.clear()
        self.modification_cache.clear()
        self.measurement_schema_map.clear()
        self.chunk_writer_cache.clear()

    def get_schema(self, path: PartialPath) -> IMeasurementSchema:
        return self.measurement_schema_map.get(path)

    @staticmethod
    def get_merge_file_writer(resource):
        writer = self.file_writer_cache.get(resource)
        if writer is None:
            writer = RestorableTsFileIOWriter(FSFactoryProducer().get_fs_factory().file(f"{resource.path}.merge"))
            self.file_writer_cache[resource] = writer
        return writer

    def query_chunk_metadata(self, path: PartialPath, seq_file: TsFileResource) -> list:
        reader = self.get_file_reader(seq_file)
        return reader.chunk_metadata_list(path, True)

    @staticmethod
    def get_file_reader(resource):
        reader = self.file_reader_cache.get(resource)
        if reader is None:
            reader = TsFileSequenceReader(resource.path, True, cache_device_meta)
            self.file_reader_cache[resource] = reader
        return reader

    @staticmethod
    def get_unseq_readers(paths: list) -> list:
        path_chunks = MergeUtils.collect_unseq_chunks(paths, unseq_files, self)
        readers = [CachedUnseqResourceMergeReader(chunk, dataType) for chunk in path_chunks]
        return readers

    @staticmethod
    def get_chunk_writer(measurement_schema):
        return self.chunk_writer_cache.getOrDefault(measurement_schema, ChunkWriterImpl())

    def get_modifications(self, ts_file_resource: TsFileResource, path: PartialPath) -> list:
        modifications = modification_cache.compute_if_absent(lambda resource: [resource.mod_file().modifications()])
        path_modifications = []
        for mod in modifications:
            if mod.path.match_full_path(path):
                path_modifications.append(mod)
        return path_modifications

    def remove_file_and_writer(self, ts_file_resource) -> None:
        writer = self.file_writer_cache.pop(ts_file_resource)
        if writer is not None:
            writer.close()
            writer.get_file().delete()

    @staticmethod
    def get_seq_files():
        return seq_files

    @staticmethod
    def set_seq_files(seq_files):
        global seq_files
        seq_files = seq_files

    # ... rest of the methods ...
```

Please note that this is a direct translation from Java to Python, and it may not be perfect. You might need to adjust some parts based on your specific use case or requirements.