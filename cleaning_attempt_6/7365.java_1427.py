class Img3:
    def __init__(self, provider):
        self.magic = 0
        self.size = 0
        self.data_size = 0
        self.check_area = 0
        self.identifier = 0

        tags = []

        if isinstance(provider, bytes):
            reader = BinaryReader(provider)
        else:
            raise ValueError("Invalid provider type")

        try:
            self.magic = int.from_bytes(reader.read(4), 'little')
            self.size = int.from_bytes(reader.read(4), 'little')
            self.data_size = int.from_bytes(reader.read(4), 'little')
            self.check_area = int.from_bytes(reader.read(4), 'little')
            self.identifier = int.from_bytes(reader.read(4), 'little')

            while reader.tell() < self.size:
                tag = Img3TagFactory.get_tag(reader)
                tags.append(tag)

        except Exception as e:
            raise IOException(str(e))

    def get_magic(self):
        return str(self.magic)

    def get_size(self):
        return self.size

    def get_data_size(self):
        return self.data_size

    def get_check_area(self):
        return self.check_area

    def get_identifier(self):
        return self.identifier

    def get_tags(self, class_type=None):
        if class_type:
            tags = [tag for tag in self.tags if isinstance(tag, class_type)]
            return tags
        else:
            return self.tags

class BinaryReader:
    def __init__(self, provider):
        self.provider = provider
        self.tell() = 0

    def read(self, size):
        data = self.provider[self.tell():self.tell()+size]
        self.tell() += size
        return bytes(data)

    def tell(self):
        if isinstance(self.provider, bytes):
            return len(self.provider)
        else:
            raise ValueError("Invalid provider type")

class Img3TagFactory:
    @staticmethod
    def get_tag(reader):
        # This method should be implemented based on the actual tag factory logic.
        pass

# Usage example:

provider = b'\x00\x01\x02\x03'  # Replace with your data provider
img3 = Img3(provider)
print(img3.get_magic())
