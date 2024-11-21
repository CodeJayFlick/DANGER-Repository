class SourceFileAttribute:
    def __init__(self):
        self.source_file_index = None

    def read_from_binary_reader(self, reader):
        super().__init__()
        self.source_file_index = reader.read_next_short()

    @property
    def source_file_index(self):
        return self._source_file_index & 0xffff

    def to_data_type(self) -> dict:
        structure = {"SourceFile_attribute": {}}
        structure["SourceFile_attribute"]["u2 attribute_name_index"] = None
        structure["SourceFile_attribute"]["u4 attribute_length"] = None
        structure["SourceFile_attribute"]["u2 sourcefile_index"] = self.source_file_index

        return structure


class BinaryReader:
    def read_next_short(self):
        # Implement your binary reader logic here.
        pass


# Example usage:

reader = BinaryReader()
attribute = SourceFileAttribute()
try:
    attribute.read_from_binary_reader(reader)
except Exception as e:
    print(f"Error: {e}")

print(attribute.source_file_index)

data_type = attribute.to_data_type()
for key, value in data_type["SourceFile_attribute"].items():
    if isinstance(value, dict):
        for sub_key, sub_value in value.items():
            print(f"{key} {sub_key}: {sub_value}")
