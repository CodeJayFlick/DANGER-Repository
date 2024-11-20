Here is the translation of the Java code to Python:
```python
import io

class RuntimeVisibleAnnotationsAttribute:
    def __init__(self, reader):
        self.info_bytes = reader.read_next_byte_array(reader.get_attribute_length())

    def to_data_type(self) -> tuple:
        structure = {"RuntimeVisibleAnnotations_attribute": {}}
        if len(self.info_bytes) > 0:
            array = (b"BYTE", len(self.info_bytes), "BYTE")
            structure["RuntimeVisibleAnnotations_attribute"]["info"] = array
        return structure

# Example usage:
reader = io.BufferedReader()  # assume this is a BinaryReader equivalent in Python
attribute = RuntimeVisibleAnnotationsAttribute(reader)
data_type = attribute.to_data_type()
print(data_type)  # prints the resulting data type as a dictionary
```
Note that I've made some simplifications and assumptions to translate the code:

* In Java, `byte[]` arrays are represented as tuples of bytes in Python. I used the `b"BYTE"` syntax to represent an array of byte values.
* The `getBaseStructure()` method is not directly translatable to Python, so I replaced it with a dictionary that represents the structure.
* The `add()` method is also not directly translatable, so I simply added the "info" key-value pair to the structure dictionary.

Please note that this translation may not be perfect or idiomatic Python code. If you need further modifications or refinements, please let me know!