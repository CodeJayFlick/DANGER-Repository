class ConstantPoolClassInfo:
    def __init__(self):
        self.name_index = None

    def from_reader(self, reader):
        if not isinstance(reader, object):  # assuming BinaryReader in your case
            raise TypeError("reader must be an instance of BinaryReader")
        try:
            super().__init__()
            self.name_index = reader.read_next_short()
        except Exception as e:  # assuming IOException and other exceptions
            print(f"An error occurred while reading the file. {str(e)}")

    def get_name_index(self):
        return self.name_index & 0xffff

class DataType:
    pass

def to_data_type(self, name="CONSTANT_Class_info"):
    structure = {"tag": "BYTE", "name_index": "WORD"}
    return structure
