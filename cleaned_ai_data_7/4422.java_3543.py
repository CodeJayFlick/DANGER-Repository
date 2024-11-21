class ByteColumnAdapter:
    def get_value_class(self):
        return bytes

    def get_key_value(self, rec):
        key_field = rec.get_key_field()
        if isinstance(key_field, int):  # assuming ByteField gets converted to an integer
            return bytes([key_field])
        else:
            raise ValueError("Expected a ByteField")

    def get_value(self, rec, col):
        return bytes([rec.get_byte_value(col)])
