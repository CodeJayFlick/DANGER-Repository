class DyldCacheAcceleratorDof:
    def __init__(self):
        self.section_address = None
        self.section_size = None
        self.image_index = None

    @staticmethod
    def from_binary_reader(reader):
        try:
            section_address = reader.read_long()
            section_size = reader.read_int()
            image_index = reader.read_int()
            return DyldCacheAcceleratorDof(section_address, section_size, image_index)
        except Exception as e:
            raise IOError("Error reading DYLD accelerator DOF") from e

    def to_data_type(self):
        struct = {"sectionAddress": self.section_address,
                  "sectionSize": self.section_size,
                  "imageIndex": self.image_index}
        return struct
