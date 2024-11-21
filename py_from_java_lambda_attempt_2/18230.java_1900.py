Here's the translation of the Java interface `IChunkMetadataLoader` into a Python class:

```Python
class IChunkMetadataLoader:
    def load_chunk_metadata_list(self, timeseries_metadata):
        # Implement your logic here.
        pass  # This is just a placeholder.

    def is_mem_chunk_metadata_loader(self) -> bool:
        return False  # Default value. You can override this based on your requirements.
```

Note that Python does not have direct support for interfaces like Java, but we can achieve similar functionality using abstract classes or protocols (in Python 3.8+). In this case, I've used a regular class with placeholder methods.

The `load_chunk_metadata_list` method takes an object of type `timeseries_metadata`, which is equivalent to the `ITimeSeriesMetadata` interface in Java. You would need to implement your logic for reading chunk metadata here.

Similarly, the `is_mem_chunk_metadata_loader` method returns a boolean value indicating whether this loader uses memory-based chunk metadata or not.