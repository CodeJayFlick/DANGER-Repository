class ArtHeader10:
    def __init__(self):
        self.image_reservation_size = None
        self.component_count = None
        self.image_begin = None
        self.image_size = None
        self.image_checksum = None
        self.oat_checksum = None
        self.oat_file_begin = None
        self.oat_data_begin = None
        self.oat_data_end = None
        self.oat_file_end = None
        self.boot_image_begin = None
        self.boot_image_size = None
        self.image_roots = None
        self.pointer_size = None
        self.sections = None

    def parse(self, reader):
        try:
            self.image_reservation_size = int.from_bytes(reader.read(4), 'little')
            self.component_count = int.from_bytes(reader.read(4), 'little')
            self.image_begin = int.from_bytes(reader.read(4), 'little')
            self.image_size = int.from_bytes(reader.read(4), 'little')
            self.image_checksum = int.from_bytes(reader.read(4), 'little')
            self.oat_checksum = int.from_bytes(reader.read(4), 'little')
            self.oat_file_begin = int.from_bytes(reader.read(4), 'little')
            self.oat_data_begin = int.from_bytes(reader.read(4), 'little')
            self.oat_data_end = int.from_bytes(reader.read(4), 'little')
            self.oat_file_end = int.from_bytes(reader.read(4), 'little')
            self.boot_image_begin = int.from_bytes(reader.read(4), 'little')
            self.boot_image_size = int.from_bytes(reader.read(4), 'little')
            self.image_roots = int.from_bytes(reader.read(4), 'little')
            self.pointer_size = int.from_bytes(reader.read(4), 'little')

            if hasattr(self, 'sections'):
                del self.sections
            self.sections = ImageSections10(reader, self)
            self.sections.parse_sections(reader)

            self.parse_image_methods(reader)

        except Exception as e:
            print(f"Error parsing: {e}")

    def parse_image_methods(self, reader):
        pass

    @property
    def art_method_count_for_version(self):
        return 0

    @property
    def image_begin(self):
        return self.image_begin

    @property
    def image_size(self):
        return self.image_size

    def get_image_checksum_(self):
        return self.image_checksum

    @property
    def oat_checksum(self):
        return self.oat_checksum

    @property
    def oat_data_begin(self):
        return self.oat_data_begin

    @property
    def oat_data_end(self):
        return self.oat_data_end

    @property
    def oat_file_begin(self):
        return self.oat_file_begin

    @property
    def oat_file_end(self):
        return self.oat_file_end

    @property
    def pointer_size(self):
        return self.pointer_size

    def get_boot_image_begin(self):
        return self.boot_image_begin

    def is_app_image(self):
        if hasattr(self, 'boot_image_size'):
            del self.boot_image_size
        return self.boot_image_size != 0x0

    @property
    def image_reservation_size_(self):
        return self.image_reservation_size_

    @property
    def component_count_(self):
        return self.component_count_

    @property
    def image_roots_(self):
        return self.image_roots_

    @property
    def data_size_(self):
        return self.data_size_

    @property
    def blocks(self):
        if hasattr(self, 'blocks'):
            del self.blocks
        # TO DO: implement this method
        pass

    def markup(self, program, monitor):
        try:
            DecompressionManager.decompress_over_memory(program, self.blocks, monitor)
            self.sections.markup(program, monitor)

        except Exception as e:
            print(f"Error marking up: {e}")

    @property
    def data_type(self):
        structure = super().to_data_type()
        if hasattr(structure, 'name'):
            del structure.name

        try:
            structure.name = "ArtHeader10"
        except InvalidNameException as e:
            pass  # ignore the exception and use original name

        structure.add(DWORD("image_reservation_size"))
        structure.add(DWORD("component_count"))
        structure.add(DWORD("image_begin"))
        structure.add(DWORD("image_size"))
        structure.add(DWORD("image_checksum"))
        structure.add(DWORD("oat_checksum"))
        structure.add(DWORD("oat_file_begin"))
        structure.add(DWORD("oat_data_begin"))
        structure.add(DWORD("oat_data_end"))
        structure.add(DWORD("oat_file_end"))
        structure.add(DWORD("boot_image_begin"))
        structure.add(DWORD("boot_image_size"))
        structure.add(DWORD("image_roots"))
        structure.add(DWORD("pointer_size"))

        for i, section in enumerate(self.sections.get_section_list()):
            if hasattr(section, 'to_data_type'):
                del section.to_data_type
            try:
                structure.add(section.to_data_type(), f"section_{i}")
            except InvalidNameException as e:
                pass  # ignore the exception and use original name

        for i in range(len(self.image_methods_)):
            if hasattr(self, 'image_methods_'):
                del self.image_methods_
            try:
                structure.add(QWORD(f"image_method_{i}"))
            except InvalidNameException as e:
                pass  # ignore the exception and use original name

        return structure
