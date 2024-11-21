Here is the translation of the Java code to Python:

```Python
class MemChunkReader:
    def __init__(self, readable_chunk, filter):
        self.time_value_pair_iterator = readable_chunk.get_point_reader()
        self.filter = filter
        # we treat one ReadOnlyMemChunk as one Page
        self.page_reader_list = [MemPageReader(self.time_value_pair_iterator, readable_chunk.get_chunk_meta_data(), filter)]

    def has_next_time_value_pair(self):
        if hasattr(self, 'has_cached_time_value_pair'):
            return True
        while self.time_value_pair_iterator.has_next_time_value_pair():
            time_value_pair = self.time_value_pair_iterator.next_time_value_pair()
            if not self.filter or self.filter.satisfy(time_value_pair.get_timestamp(), time_value_pair.get_value().get_value()):
                self.has_cached_time_value_pair = True
                self.cached_time_value_pair = time_value_pair
                break
        return hasattr(self, 'has_cached_time_value_pair')

    def next_time_value_pair(self):
        if hasattr(self, 'has_cached_time_value_pair'):
            delattr(self, 'has_cached_time_value_pair')
            return self.cached_time_value_pair
        else:
            return self.time_value_pair_iterator.next_time_value_pair()

    def current_time_value_pair(self):
        if not hasattr(self, 'has_cached_time_value_pair'):
            self.cached_time_value_pair = self.time_value_pair_iterator.next_time_value_pair()
            self.has_cached_time_value_pair = True
        return self.cached_time_value_pair

    def has_next_satisfied_page(self):
        return self.has_next_time_value_pair()

    def next_page_data(self):
        return self.page_reader_list.pop(0).get_all_satisfied_page_data()

    def close(self):
        # Do nothing because mem chunk reader will not open files
        pass

    def load_page_reader_list(self):
        return self.page_reader_list


class MemPageReader:
    def __init__(self, time_value_pair_iterator, chunk_meta_data, filter):
        self.time_value_pair_iterator = time_value_pair_iterator
        self.chunk_meta_data = chunk_meta_data
        self.filter = filter

    def has_next_time_value_pair(self):
        return self.time_value_pair_iterator.has_next_time_value_pair()

    def next_time_value_pair(self):
        return self.time_value_pair_iterator.next_time_value_pair()

    def get_all_satisfied_page_data(self):
        # This method should be implemented based on the actual requirements
        pass


# Example usage:
readable_chunk = ...  # Initialize readable chunk object
filter = ...  # Initialize filter object

mem_chunk_reader = MemChunkReader(readable_chunk, filter)

while mem_chunk_reader.has_next_time_value_pair():
    time_value_pair = mem_chunk_reader.next_time_value_pair()
    print(time_value_pair.get_timestamp(), time_value_pair.get_value().get_value())

# Close the reader
mem_chunk_reader.close()

page_readers = mem_chunk_reader.load_page_reader_list()
for page_reader in page_readers:
    batch_data = page_reader.get_all_satisfied_page_data()
    # Process the batch data as needed
```

Please note that this is a direct translation of Java code to Python, and it may not be perfect. You might need to adjust some parts based on your actual requirements.