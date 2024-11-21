Here is the translation of the Java interface `InputBlockStream` into a Python class:

```python
import io

class InputBlockStream:
    def read_block(self) -> 'BufferFileBlock' or None:
        # implement your logic here to read next block from stream
        pass  # return BufferFileBlock instance or None if no more blocks available

    @property
    def block_count(self):
        # implement your logic here to get the total number of blocks to be transferred
        raise NotImplementedError("getBlockCount not implemented")

    @property
    def includes_header_block(self) -> bool:
        # implement your logic here to determine if header block included in stream
        return False  # default value, override as needed

class BufferFileBlock:  # assuming this is a custom class for buffer file blocks
    pass
```

Note that I've translated the Java interface into a Python class with similar methods and properties. The `read_block` method returns either an instance of `BufferFileBlock` or `None`, depending on whether there are more blocks available in the stream.

The `block_count` property is implemented as a read-only attribute, which means it can only be accessed but not modified. You'll need to implement your own logic for calculating this value.

Similarly, the `includes_header_block` property returns a boolean indicating whether the header block is included in the stream. This default implementation always returns `False`, so you should override this method as needed based on your specific use case.

The custom class `BufferFileBlock` represents an instance of a buffer file block and can be used to store or manipulate data related to these blocks.