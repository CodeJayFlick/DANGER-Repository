class FatArch:
    def __init__(self):
        self.cputype = None
        self.cpusubtype = None
        self.offset = None
        self.size = None
        self.align = None

    @classmethod
    def create_fat_arch(cls, reader):
        fat_arch = cls()
        fat_arch.init_fat_arch(reader)
        return fat_arch

    def init_fat_arch(self, reader):
        try:
            self.cputype = int.from_bytes(reader.read(4), 'little')
            self.cpusubtype = int.from_bytes(reader.read(4), 'little')
            self.offset = int.from_bytes(reader.read(4), 'little')
            self.size = int.from_bytes(reader.read(4), 'little')
            self.align = int.from_bytes(reader.read(4), 'little')
        except Exception as e:
            print(f"Error: {e}")

    def get_cpu_type(self):
        return self.cputype

    def get_cpu_subtype(self):
        return self.cpusubtype

    def get_offset(self):
        return self.offset

    def get_size(self):
        return self.size

    def get_align(self):
        return self.align

    def __str__(self):
        buffer = ""
        buffer += f"CPU Type: 0x{self.cputype:x}\n"
        buffer += f"CPU Sub Type: 0x{self.cpusubtype:x}\n"
        buffer += f"Offset: 0x{self.offset:x}\n"
        buffer += f"Size: 0x{self.size:x}\n"
        buffer += f"Align: 0x{self.align:x}\n"
        return buffer
