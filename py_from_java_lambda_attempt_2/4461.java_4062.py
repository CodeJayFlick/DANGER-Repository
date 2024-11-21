Here is the translation of the Java code into Python:

```Python
class RegionDescriptor:
    def __init__(self):
        self.eh_memory = None
        self.lsda_address = None
        self.lsda_table = None
        self.fde = None
        self.ip_range = (None, None)

    @property
    def eh_memory_block(self):
        return self.eh_memory

    @eh_memory_block.setter
    def eh_memory_block(self, value):
        self.eh_memory = value

    @property
    def ip_range(self):
        return self.ip_range

    @ip_range.setter
    def ip_range(self, value):
        self.ip_range = value

    @property
    def range_start(self):
        if not self.ip_range:
            return None
        return self.ip_range[0]

    @property
    def range_size(self):
        if not self.ip_range:
            return 0
        return abs(self.ip_range[1] - self.ip_range[0])

    def set_lsda_address(self, address):
        self.lsda_address = address

    def get_lsda_address(self):
        return self.lsda_address

    @property
    def lsda_table(self):
        return self.lsda_table

    @lsda_table.setter
    def lsda_table(self, value):
        self.lsda_table = value

    def set_frame_descriptor_entry(self, frame_description_entry):
        self.fde = frame_description_entry

    def get_frame_descriptor_entry(self):
        return self.fde


class AddressRange:
    def __init__(self, start=None, end=None):
        if not isinstance(start, int) or not isinstance(end, int):
            raise ValueError("Start and End must be integers")
        self.start = start
        self.end = end

    @property
    def min_address(self):
        return self.start

    @property
    def length(self):
        return abs(self.end - self.start)
```

Please note that Python does not have direct equivalent of Java's `Address` class. I've used tuples to represent the range, and you can use this as a starting point for your own implementation if needed.