class AndroidBootLoaderImageInfo:
    def __init__(self):
        self.name = None
        self.size = 0

    def read_from_binary(self, reader):
        try:
            self.name = reader.read_ascii_string(AndroidBootLoaderConstants.IMG_INFO_NAME_LENGTH).strip()
            self.size = int(reader.read_next_int())
        except Exception as e:
            print(f"Error reading from binary: {e}")

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        if not isinstance(value, int):
            raise TypeError("Size must be an integer")
        self._size = value

class StructureDataType:
    def __init__(self, name, offset=0):
        self.name = name
        self.offset = offset
        self.fields = []

    def add(self, field_type, field_name=None, default_value=None):
        if not isinstance(field_type, str) or not isinstance(field_name, str):
            raise TypeError("Field type and name must be strings")
        self.fields.append((field_type, field_name, default_value))

def to_data_type(self):
    struct = StructureDataType(AndroidBootLoaderConstants.IMG_INFO_NAME)
    struct.add('STRING', 'magic', None)
    struct.add('DWORD', 'size', None)
    return struct
