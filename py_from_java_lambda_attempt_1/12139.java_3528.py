Here is the translation of the Java code into Python:

```Python
class Address:
    NO_ADDRESS = None
    EXT_FROM_ADDRESS = None

    SEPARATOR_CHAR = ':'

    def __init__(self):
        pass

    @staticmethod
    def get_address(addr_string):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    @staticmethod
    def get_new_address(byte_offset):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    @staticmethod
    def get_new_truncated_address(offset, is_addressable_word_offset):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def get_pointer_size(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def next(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def previous(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    @property
    def offset(self):
        # TO DO: implement getter and setter for 'offset' property
        pass

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def size(self):
        # TO DO: implement getter and setter for 'size' property
        pass

    @size.setter
    def size(self, value):
        self._size = value

    def subtract(self, displacement):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def add_no_wrap(self, displacement):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def __eq__(self, other):
        if isinstance(other, Address):
            return self.offset == other.offset and self.size == other.size
        else:
            return False

    def __hash__(self):
        return hash(self.offset)

    @property
    def physical_address(self):
        # TO DO: implement getter and setter for 'physical_address' property
        pass

    @physical_address.setter
    def physical_address(self, value):
        self._physical_address = value

    def is_memory_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_loaded_memory_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_non_loaded_memory_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_stack_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_unique_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_constant_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_hash_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_register_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    def is_variable_address(self):
        # TO DO: implement this method in Python
        raise NotImplementedError("Method not implemented")

    @staticmethod
    def min(a, b):
        if a.offset < b.offset:
            return a
        else:
            return b

    @staticmethod
    def max(a, b):
        if a.offset > b.offset:
            return a
        else:
            return b

# Example usage:

addr1 = Address()
addr2 = Address()

print(addr1.is_memory_address())  # TO DO: implement this method in Python
```

Please note that the above code is just an example of how you might translate the Java code into Python. The actual implementation will depend on your specific requirements and constraints.