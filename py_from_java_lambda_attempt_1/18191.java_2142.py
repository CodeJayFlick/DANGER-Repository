Here is the translation of the given Java code into Python:

```Python
class MetadataIndexNode:
    def __init__(self):
        self.children = []
        self.end_offset = -1
        self.node_type = None

    def get_children(self):
        return self.children

    def set_end_offset(self, end_offset):
        self.end_offset = end_offset

    def get_node_type(self):
        return self.node_type

    def add_entry(self, metadata_index_entry):
        self.children.append(metadata_index_entry)

    @property
    def is_full(self):
        if len(self.children) >= config.get_max_degree_of_index_node():
            return True
        else:
            return False

    def peek(self):
        if not self.children:
            return None
        return self.children[0]

    def serialize_to(self, output_stream):
        byte_len = 0
        byte_len += ReadWriteForEncodingUtils.write_unsigned_var_int(len(self.children), output_stream)
        for metadata_index_entry in self.children:
            byte_len += metadata_index_entry.serialize_to(output_stream)
        byte_len += ReadWriteIOUtils.write(self.end_offset, output_stream)
        byte_len += ReadWriteIOUtils.write(self.node_type.serialize(), output_stream)
        return byte_len

    @classmethod
    def deserialize_from(cls, buffer):
        children = []
        size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer)
        for _ in range(size):
            children.append(MetadataIndexEntry.deserialize_from(buffer))
        offset = ReadWriteIOUtils.read_long(buffer)
        node_type = MetadataIndexNodeType.deserialize(ReadWriteIOUtils.read_byte(buffer))
        return cls(children, offset, node_type)

    def get_child_index_entry(self, key, exact_search=False):
        index = self.binary_search_in_children(key, exact_search)
        if index == -1:
            return None
        child_end_offset = children[index + 1].get_offset() if index != len(self.children) - 1 else self.end_offset
        return (children[index], child_end_offset)

    def binary_search_in_children(self, key, exact_search=False):
        low = 0
        high = len(self.children) - 1

        while low <= high:
            mid = (low + high) // 2
            mid_val = self.children[mid]
            cmp = mid_val.get_name().compareTo(key)

            if cmp < 0:
                low = mid + 1
            elif cmp > 0:
                high = mid - 1
            else:
                return mid

        # key not found
        if exact_search:
            return -1
        else:
            return low == 0 or low - 1


class MetadataIndexEntry:
    def __init__(self):
        pass

    @classmethod
    def deserialize_from(cls, buffer):
        pass

    def serialize_to(self, output_stream):
        pass

    def get_name(self):
        pass

    def get_offset(self):
        pass
```

Note: The above Python code is a direct translation of the given Java code. However, it may not be perfect as some parts might require additional information or context that was missing in the original Java code.