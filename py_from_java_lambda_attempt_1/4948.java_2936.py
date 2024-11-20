Here's your requested translation:

```Python
class OmfData:
    def __init__(self):
        pass

    def get_data_offset(self) -> int:
        # implement this method as needed
        return 0

    def get_length(self) -> int:
        # implement this method as needed
        return 0

    def get_byte_array(self, reader: 'BinaryReader') -> bytes:
        try:
            byte_array = bytearray(reader.read(get_length()))
            return bytes(byte_array)
        except Exception as e:
            raise IOException(str(e))

    def is_all_zeroes(self) -> bool:
        # implement this method as needed
        return False

class BinaryReader:
    pass  # implement your binary reader class here
```

Note that Python doesn't have direct equivalents for Java's `public` and `throws`, so I've omitted those. Also, the `Comparable<OmffData>` interface is not directly translatable to Python (since it relies on Java-specific features), but you could use a similar approach with Python's built-in comparison operators if needed.

The above code assumes that your binary reader class (`BinaryReader`) has methods for reading data from an image. You would need to implement this class according to the specific requirements of your project.