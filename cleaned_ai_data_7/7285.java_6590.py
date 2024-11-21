class Ext4ExtentHeader:
    SIZEOF = 12
    
    def __init__(self):
        self.eh_magic = None
        self.eh_entries = None
        self.eh_max = None
        self.eh_depth = None
        self.eh_generation = None

    @classmethod
    def read(cls, reader: bytes) -> 'Ext4ExtentHeader':
        if len(reader) < cls.SIZEOF or int.from_bytes(reader[:2], byteorder='little') != 0x53465400:
            return None
        
        obj = Ext4ExtentHeader()
        obj.eh_magic = int.from_bytes(reader[0:2], byteorder='little')
        obj.eh_entries = int.from_bytes(reader[2:4], byteorder='little')
        obj.eh_max = int.from_bytes(reader[4:6], byteorder='little')
        obj.eh_depth = int.from_bytes(reader[6:8], byteorder='little')
        obj.eh_generation = int.from_bytes(reader[8:], byteorder='little')

        return obj

    def get_eh_magic(self):
        return self.eh_magic

    def get_eh_entries(self):
        return self.eh_entries

    def get_eh_max(self):
        return self.eh_max

    def get_eh_depth(self):
        return self.eh_depth

    def get_eh_generation(self):
        return self.eh_generation

    @classmethod
    def to_data_type(cls) -> dict:
        data_type = {
            "ext4_extent_header": {
                "fields": [
                    {"name": "eh_magic", "type": "short"},
                    {"name": "eh_entries", "type": "short"},
                    {"name": "eh_max", "type": "short"},
                    {"name": "eh_depth", "type": "short"},
                    {"name": "eh_generation", "type": "int"}
                ]
            }
        }

        return data_type
