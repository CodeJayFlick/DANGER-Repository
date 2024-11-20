class WideChar32DataType:
    def __init__(self):
        self.data_type = None
        self.description = "Wide-Character (32-bit/UTF32)"
    
    @property
    def data_type(self):
        return self._data_type
    
    @data_type.setter
    def data_type(self, value):
        if isinstance(value, WideChar32DataType):
            self._data_type = value
        else:
            raise ValueError("Invalid data type")
    
    def get_length(self):
        return 4

    def get_description(self):
        return "Wide-Character (32-bit/UTF32)"

    def clone(self):
        if self.data_type is None:
            return WideChar32DataType()
        else:
            return WideChar32DataType()

    def get_mnemonic(self, settings=None):
        return "wchar32"

    def get_representation(self, buf, settings=None, length=4):
        return str(buf.get_int(0))

    def get_value(self, buf, settings=None, length=4):
        try:
            value = buf.get_int(0)
            if isinstance(value, int) and 0 <= value < 2**32:
                return f"U+{value:04X}"
            else:
                raise ValueError("Invalid Unicode code point")
        except Exception as e:
            print(f"Error getting value: {e}")
    
    def is_encodable(self):
        return True

    def encode_value(self, value, buf, settings=None, length=4):
        if isinstance(value, str) and len(value) <= 1:
            try:
                code_point = int.from_bytes(value.encode(), 'big')
                buf.set_int(0, code_point)
                return bytearray([code_point])
            except Exception as e:
                print(f"Error encoding value: {e}")
        else:
            raise ValueError("Invalid Unicode string")

    def encode_representation(self, repr, buf, settings=None, length=4):
        if isinstance(repr, str) and len(repr) <= 1:
            try:
                code_point = int.from_bytes(repr.encode(), 'big')
                buf.set_int(0, code_point)
                return bytearray([code_point])
            except Exception as e:
                print(f"Error encoding representation: {e}")
        else:
            raise ValueError("Invalid Unicode string")

    def get_value_class(self):
        return type(None)

    def default_label_prefix(self, settings=None, length=4):
        if isinstance(settings, dict) and 'mem_buffer' in settings:
            buf = settings['mem_buffer']
            try:
                value = buf.get_int(0)
                if 0 <= value < 2**32:
                    return f"WCHAR32_{value:04X}"
                else:
                    raise ValueError("Invalid Unicode code point")
            except Exception as e:
                print(f"Error getting default label prefix: {e}")
        else:
            return "WCHAR32"

    def has_string_value(self):
        return True

class StringDataInstance:
    def __init__(self, data_type, settings=None, buf=None, length=4, is_array=False):
        self.data_type = data_type
        self.settings = settings
        self.buf = buf
        self.length = length
        self.is_array = is_array
    
    def get_label(self, prefix="", offcut_prefix="", label=""):
        if isinstance(prefix, str) and len(prefix) > 0:
            return f"{prefix}_{self.data_type.get_default_label_prefix()}"
        else:
            return self.data_type.default_label_prefix()

    def get_offcut_label_string(self, prefix="", offcut_prefix="", label=""):
        if isinstance(prefix, str) and len(prefix) > 0:
            return f"{offcut_prefix}_{self.data_type.get_array_default_label_prefix()}"
        else:
            return self.data_type.get_array_default_label_prefix()

    def get_charsetName(self):
        return "UTF32"
