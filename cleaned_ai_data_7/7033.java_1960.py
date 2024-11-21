class ArtHeaderKitKat:
    def __init__(self):
        self.image_begin = None
        self.image_size = None
        self.image_bitmap_offset = None
        self.image_bitmap_size = None
        self.oat_checksum = None
        self.oat_file_begin = None
        self.oat_data_begin = None
        self.oat_data_end = None
        self.oat_file_end = None
        self.image_roots = None

    def parse(self):
        if not all([self.image_begin, self.image_size, 
                    self.image_bitmap_offset, self.image_bitmap_size,
                    self.oat_checksum, self.oat_file_begin, self.oat_data_begin, 
                    self.oat_data_end, self.oat_file_end, self.image_roots]):
            raise ValueError("All fields must be set before parsing")

    def get_image_begin(self):
        return self.image_begin

    def get_image_size(self):
        return self.image_size

    def get_image_bitmap_offset(self):
        return self.image_bitmap_offset

    def get_image_bitmap_size(self):
        return self.image_bitmap_size

    def get_oat_checksum(self):
        return self.oat_checksum

    def get_oat_file_begin(self):
        return self.oat_file_begin

    def get_oat_data_begin(self):
        return self.oat_data_begin

    def get_oat_data_end(self):
        return self.oat_data_end

    def get_oat_file_end(self):
        return self.oat_file_end

    def get_image_roots(self):
        return self.image_roots
