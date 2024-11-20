class OmfData:
    def __init__(self):
        pass

    def get_data_offset(self) -> int:
        # implement this method as needed
        return 0

    def get_length(self) -> int:
        # implement this method as needed
        return 0

    def get_byte_array(self, reader: 'BinaryReader') -> bytes:
        try:
            byte_array = bytearray(reader.read(get_length()))
            return bytes(byte_array)
        except Exception as e:
            raise IOException(str(e))

    def is_all_zeroes(self) -> bool:
        # implement this method as needed
        return False

class BinaryReader:
    pass  # implement your binary reader class here
