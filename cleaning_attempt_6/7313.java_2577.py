class Apple8900Header:
    def __init__(self, provider):
        self.magic = None
        self.version = None
        self.encrypted = None
        self.unknown0 = None
        self.size_of_data = 0
        self.footer_signature_offset = 0
        self.footer_cert_offset = 0
        self.footer_cert_length = 0
        self.key1 = None
        self.unknown1 = None
        self.key2 = None
        self.unknown2 = None

    def read_from_provider(self, provider):
        reader = BinaryReader(provider, True)
        self.magic = reader.read_next_byte_array(4)
        self.version = reader.read_next_byte_array(3)
        self.encrypted = reader.read_next_byte()
        self.unknown0 = reader.read_next_byte_array(4)
        self.size_of_data = reader.read_next_int()
        self.footer_signature_offset = reader.read_next_int()
        self.footer_cert_offset = reader.read_next_int()
        self.footer_cert_length = reader.read_next_int()
        self.key1 = reader.read_next_byte_array(20)
        self.unknown1 = reader.read_next_byte_array(4)
        self.key2 = reader.read_next_byte_array(10)
        self.unknown2 = reader.read_next_byte_array(1170)

    def get_magic(self):
        return ''.join(map(chr, self.magic))

    def get_version(self):
        return ''.join(map(lambda x: chr(x), reversed(self.version)))

    def is_encrypted(self):
        return self.encrypted == Apple8900Constants.FORMAT_ENCRYPTED

    def get_size_of_data(self):
        return self.size_of_data

    def get_footer_signature_offset(self):
        return self.footer_signature_offset

    def get_footer_certificate_offset(self):
        return self.footer_cert_offset

    def get_footer_certificate_length(self):
        return self.footer_cert_length

    def get_key1(self):
        return self.key1

    def get_key2(self):
        return self.key2

    def get_unknown(self, index):
        if index == 0:
            return self.unknown0
        elif index == 1:
            return self.unknown1
        elif index == 2:
            return self.unknown2
        else:
            raise RuntimeError("Invalid unknown index")

class BinaryReader:
    def __init__(self, provider, big_endian):
        pass

    def read_next_byte_array(self, size):
        # implement this method to read the byte array from the provider
        pass

    def read_next_int(self):
        # implement this method to read an integer from the provider
        pass

class Apple8900Constants:
    FORMAT_ENCRYPTED = 1
