class RichHeader:
    IMAGE_RICH_SIGNATURE = 0x68636952
    IMAGE_DANS_SIGNATURE = 0x536E6144
    NAME = "IMAGE_RICH_HEADER"

    def __init__(self):
        pass

    @classmethod
    def create_rich_header(cls, reader):
        rich_header = cls()
        rich_header.init_rich_header(reader)
        return rich_header

    def init_rich_header(self, binary_reader):
        self.reader = binary_reader
        self.parse()

    def parse(self):
        curr_pos = self.reader.tell()
        table = RichTable(self.reader)

        if table.size == 0:
            self.reader.seek(curr_pos)
            return

        self.reader.seek(table.offset + table.size)

    @property
    def offset(self):
        return -1 if not hasattr(self, 'table') else int(self.table.offset)

    @property
    def size(self):
        return 0 if not hasattr(self, 'table') else self.table.size

    @property
    def mask(self):
        return -1 if not hasattr(self, 'table') else self.table.mask

    @property
    def records(self):
        return [] if not hasattr(self, 'table') else self.table.records

    def to_data_type(self):
        if self.table.size == 0:
            return None
        return self.table.to_data_type()

    def write(self, raf, dc):
        if hasattr(self, 'table'):
            raf.write(dc.encode(b'\x52\x63\x68'))  # IMAGE_RICH_SIGNATURE

            raf.write(dc.encode(int_to_bytes(table.mask)))  # 0 ^ mask
            raf.write(dc.encode(int_to_bytes(table.mask)))  # 0 ^ mask
            raf.write(dc.encode(int_to_bytes(table.mask)))  # 0 ^ mask

            for rec in self.table.records:
                raf.write(dc.encode(rec.comp_id.value ^ table.mask))
                raf.write(dc.encode(rec.object_count ^ table.mask))

            raf.write(dc.encode(b'\x52\x63\x68'))  # IMAGE_RICH_SIGNATURE
            raf.write(dc.encode(int_to_bytes(table.mask)))

def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')
