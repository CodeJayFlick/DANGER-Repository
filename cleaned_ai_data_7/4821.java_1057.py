class DyldCacheSlideInfoCommon:
    def __init__(self):
        self.version = None

    @classmethod
    def from_binary_reader(cls, reader):
        try:
            self.version = int.from_bytes(reader.read(4), 'little')
        except Exception as e:
            raise IOException("Error reading binary file") from e

    def get_version(self):
        return self.version


class StructureDataType:
    def __init__(self, name, size):
        self.name = name
        self.size = size
        self.fields = []

    def add(self, field_type, field_name, description=""):
        self.fields.append((field_type, field_name, description))

    def set_category_path(self, category_path):
        self.category_path = category_path

    def to_data_type(self):
        return {"name": self.name,
                "size": self.size,
                "fields": self.fields,
                "category_path": self.category_path}
