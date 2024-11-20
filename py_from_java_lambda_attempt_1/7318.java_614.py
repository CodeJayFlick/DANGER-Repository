Here is the translation of the given Java code into Python:

```Python
class BTreeNodeDescriptor:
    def __init__(self):
        self.f_link = None
        self.b_link = None
        self.kind = None
        self.height = None
        self.num_records = None
        self.reserved = None

        self._record_offsets = []
        self._records = []

    def read(self, reader):
        self.f_link = reader.read_int()
        self.b_link = reader.read_int()
        self.kind = reader.read_byte()
        self.height = reader.read_byte()
        self.num_records = reader.read_short()
        self.reserved = reader.read_short()

    def read_record_offsets(self, reader, node_start_index, header):
        position = node_start_index + header.node_size - 2
        while True:
            record_offset = reader.read_short(position)
            if record_offset == 0:
                break
            self._record_offsets.append(record_offset)
            position -= 2

    def read_records(self, reader, node_start_index):
        for i in range(self.num_records):
            offset = self.get_record_offsets()[i]
            record_index = (offset & 0xffff) + node_start_index
            reader.set_pointer_index(record_index)

            record = BTreeNodeRecord(reader, self)
            self._records.append(record)

    def get_record_offsets(self):
        return self._record_offsets

    def get_records(self):
        return self._records

    @property
    def f_link(self):
        return self.f_link

    @f_link.setter
    def f_link(self, value):
        self.f_link = value

    @property
    def b_link(self):
        return self.b_link

    @b_link.setter
    def b_link(self, value):
        self.b_link = value

    @property
    def kind(self):
        return self.kind

    @kind.setter
    def kind(self, value):
        self.kind = value

    @property
    def height(self):
        return self.height

    @height.setter
    def height(self, value):
        self.height = value

    @property
    def num_records(self):
        return self.num_records

    @num_records.setter
    def num_records(self, value):
        self.num_records = value

    @property
    def reserved(self):
        return self.reserved

    @reserved.setter
    def reserved(self, value):
        self.reserved = value


class BTreeNodeRecord:
    pass  # This class is not implemented in the given Java code. It seems to be a custom data structure.
```

Please note that this translation assumes that you have already defined `BinaryReader` and other classes (like `BTreeHeaderRecord`) as they are used throughout the code but their implementation was not provided.