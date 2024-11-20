class SearchData:
    def __init__(self, input_string=None, search_bytes=None, mask=None):
        self.is_valid_input_data = True if input_string else False
        self.is_valid_search_data = True if (input_string and search_bytes) else False
        self.input_string = input_string
        self.bytes = bytearray(search_bytes or [])  # equivalent to new byte[0]
        self.mask = mask

    def get_bytes(self):
        return bytes(self.bytes)

    def get_mask(self):
        return bytes(self.mask)

    def is_valid_input_data(self):
        return self.is_valid_input_data

    def is_valid_search_data(self):
        return self.is_valid_search_data

    def get_input_string(self):
        return self.input_string

    def get_status_message(self, error_message=None):
        if not error_message:
            return None
        else:
            return error_message

    def get_hex_string(self):
        hex_string = ""
        for byte in self.bytes:
            hex_byte = format(byte & 0xff, '02x')
            hex_string += f"{hex_byte} "
        return hex_string.strip()
