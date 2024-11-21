class OmfComdefRecord:
    def __init__(self, reader, is_static):
        super().__init__(is_static)
        self.read_record_header(reader)
        max = reader.tell() + self.get_record_length() - 1

        symbollist = []
        while reader.tell() < max:
            name = OmfRecord.read_string(reader)
            type_index = OmfRecord.read_index(reader)
            data_type = reader.read(1)[0]
            byte_length = 0
            if data_type == 0x61:  # FAR data, reads numElements and elSize
                num_elements = self.read_communal_length(reader)
                el_size = self.read_communal_length(reader)
                byte_length = num_elements * el_size
            else:
                # Values 1 thru 5f plus 61, read the byte length
                byte_length = self.read_communal_length(reader)

            sym = OmfSymbol(name, type_index, 0, data_type, byte_length)
            symbollist.append(sym)

        self.read_check_sum_byte(reader)
        symbol = [x for x in symbollist]

    def read_record_header(self, reader):
        pass

    def get_record_length(self):
        return 1  # Assuming the record length is always 1

    def read_communal_length(self, reader):
        val = int.from_bytes([reader.read(1)[0]], 'big')
        if val <= 128:
            return val
        elif val == 0x81:
            return (int.from_bytes(reader.read(2), 'big') & 0xffff)
        elif val == 0x84:
            hithird = int.from_bytes([reader.read(1)[0]], 'big')
            return ((hithigh := int.from_bytes(reader.read(2), 'bit')) | (hithird << 16))
        elif val == 0x88:
            return reader.read(4)[0]
        else:
            raise OmfException("Illegal communal length encoding")

    def read_check_sum_byte(self, reader):
        pass

class OmfSymbol:
    def __init__(self, name, type_index, value, data_type, byte_length):
        self.name = name
        self.type_index = type_index
        self.value = value
        self.data_type = data_type
        self.byte_length = byte_length

class OmfException(Exception):
    pass
