Here is the translation of the given Java code into equivalent Python:

```Python
class Img2:
    def __init__(self, provider):
        self.signature = None
        self.image_type = None
        self.unknown0 = None
        self.security_epoch = None
        self.flags1 = None
        self.data_len_padded = None
        self.data_len = None
        self.unknown1 = None
        self.flags2 = None
        self.reserved = None
        self.unknown2 = None
        self.header_checksum = None
        self.checksum2 = None
        self.unknown3 = None

    def from_binary_reader(self, reader):
        if provider is not None:
            try:
                self.signature = int.from_bytes(reader.read(4), 'little')
                self.image_type = int.from_bytes(reader.read(4), 'little')
                self.unknown0 = reader.read(2)
                self.security_epoch = int.from_bytes(reader.read(2), 'little')
                self.flags1 = int.from_bytes(reader.read(4), 'little')
                self.data_len_padded = int.from_bytes(reader.read(4), 'little')
                self.data_len = int.from_bytes(reader.read(4), 'little')
                self.unknown1 = reader.read(4)
                self.flags2 = int.from_bytes(reader.read(4), 'little')
                self.reserved = reader.read(64)  # Assuming the size of reserved is 0x40
                self.unknown2 = reader.read(4)
                self.header_checksum = int.from_bytes(reader.read(4), 'little')
                self.checksum2 = int.from_bytes(reader.read(4), 'little')
                self.unknown3 = reader.read(940)  # Assuming the size of unknown3 is 0x394
            except Exception as e:
                print(f"Error: {e}")
        else:
            raise ValueError("Invalid provider")

    def get_signature(self):
        return str(self.signature)

    def get_image_type(self):
        return str(self.image_type)

    def get_security_epoch(self):
        return self.security_epoch

    def get_flags1(self):
        return self.flags1

    def get_data_len_padded(self):
        return self.data_len_padded

    def get_data_len(self):
        return self.data_len

    def get_flags2(self):
        return self.flags2

    def get_reserved(self):
        return self.reserved

    def get_header_checksum(self):
        return self.header_checksum

    def get_checksum2(self):
        return self.checksum2

    def get_unknown(self, index):
        if index == 0:
            return self.unknown0
        elif index == 1:
            return self.unknown1
        elif index == 2:
            return self.unknown2
        elif index == 3:
            return self.unknown3
        else:
            raise ValueError("Invalid unknown index")
```

Please note that Python does not have direct equivalent of Java's `ByteProvider` and `BinaryReader`. In this translation, I've assumed the provider is a file-like object or any other source from which you can read bytes.