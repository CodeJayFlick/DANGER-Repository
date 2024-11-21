Here is the translation of the Java interface `IChunkLoader` to a Python class:

```python
import io

class IChunkLoader:
    def load_chunk(self, chunk_metadata: dict) -> bytes:
        """Read all content of any chunk."""
        # TO DO: implement this method in your specific use case
        pass

    def close(self):
        """Close the file reader."""
        raise NotImplementedError("Method not implemented")
```

Note that I've used a Python class instead of an interface, as interfaces are not directly translatable to Python. The `load_chunk` method is defined with a dictionary parameter and returns bytes (equivalent to Java's `Chunk`). The `close` method raises a `NotImplementedError`, indicating that it needs to be implemented in the specific use case.

Please note that this translation assumes you want to keep the same structure and naming conventions as the original Java code.