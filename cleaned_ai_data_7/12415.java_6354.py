class Undefined7DataType:
    serialVersionUID = 1

    dataType = None

    def __init__(self):
        self.dataTypeManager = None
        super().__init__("undefined7", self.dataTypeManager)

    @classmethod
    def put(cls, key, value):
        ClassTranslator.put(key, value)

    def get_length(self):
        return 7

    def get_description(self):
        return "Undefined 7-Byte"

    def get_mnemonic(self, settings):
        return self.name

    def get_value(self, buf):
        try:
            val = (buf.get_int(0) << 24) + ((buf.get_short(4) & 0xffff) << 8) + (buf.get_byte(6) & 0xff)
            return val & 0xffffffffffff
        except MemoryAccessException as e:
            pass

    def get_representation(self, buf, settings, length):
        try:
            b = self.get_value(buf)
            val = hex(b).upper()
            val = val.zfill(14, 'h', True)
        except MemoryAccessException as e:
            pass
        return val

    def get_value(self, buf, settings, length):
        try:
            return Scalar(56, self.get_value(buf))
        except MemoryAccessException as e:
            return None

    def clone(self, dtm):
        if dtm == self.dataTypeManager:
            return self
        return Undefined7DataType(dtm)
