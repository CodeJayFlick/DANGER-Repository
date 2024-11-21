class Undefined5DataType:
    serialVersionUID = 1
    
    dataType = None

    def __init__(self):
        self.dataType = "undefined5"

    @classmethod
    def put(cls, key, value):
        ClassTranslator.put(key, value)

    def get_length(self):
        return 5

    def get_description(self):
        return "Undefined 5-Byte"

    def get_mnemonic(self, settings):
        return self.dataType

    def get_value(self, buf):
        try:
            val = (buf.get_int(0) << 8) + (buf.get_byte(4) & 0xff)
            return val
        except MemoryAccessException as e:
            pass

    def get_representation(self, buf, settings, length):
        val = "??"
        
        try:
            b = self.get_value(buf)
            val = hex(b)[2:].upper()
            val = val.zfill(10, '0')
        except Exception as e:
            pass
        
        return val

    def get_value(self, buf, settings, length):
        try:
            return Scalar(40, self.get_value(buf))
        except MemoryAccessException as e:
            return None

    def clone(self, dtm):
        if dtm == self.dataTypeManager():
            return self
        return Undefined5DataType(dtm)
