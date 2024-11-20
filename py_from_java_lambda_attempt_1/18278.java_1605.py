Here's a translation of your Java code into equivalent Python:

```Python
class TsFileTimeGenerator:
    def __init__(self, iexpression, chunk_loader, metadata_querier):
        self.chunk_loader = chunk_loader
        self.metadata_querier = metadata_querier
        
        super().__init__(iexpression)

    @property
    def is_ascending(self):
        return True

    def generate_new_batch_reader(self, expression):
        try:
            chunk_metadata_list = self.metadata_querier.get_chunk_meta_data_list(expression.series_path)
            return FileSeriesReader(self.chunk_loader, chunk_metadata_list, expression.filter)
        except Exception as e:
            raise
```

Please note that Python does not have direct equivalent of Java's interfaces and abstract classes. In this translation, I've used regular classes to represent the interfaces in your original code.

Also, Python does not support checked exceptions like Java does. The `try/except` block is used here for error handling instead.