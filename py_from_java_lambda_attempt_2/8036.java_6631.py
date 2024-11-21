Here is the translation of the given Java code into Python:

```Python
class RvaVaDebugHeader:
    def __init__(self):
        self.relative_virtual_address_data_base = 0
        self.virtual_address_image_base = 0
        self.unsigned_int_reserved1 = 0
        self.unsigned_int_reserved2 = 0

    @property
    def relative_virtual_address_data_base(self):
        return self.relative_virtual_address_data_base

    @relative_virtual_address_data_base.setter
    def relative_virtual_address_data_base(self, value):
        self.relative_virtual_address_data_base = value

    @property
    def virtual_address_image_base(self):
        return self.virtual_address_image_base

    @virtual_address_image_base.setter
    def virtual_address_image_base(self, value):
        self.virtual_address_image_base = value

    @property
    def unsigned_int_reserved1(self):
        return self.unsigned_int_reserved1

    @unsigned_int_reserved1.setter
    def unsigned_int_reserved1(self, value):
        self.unsigned_int_reserved1 = value

    @property
    def unsigned_int_reserved2(self):
        return self.unsigned_int_reserved2

    @unsigned_int_reserved2.setter
    def unsigned_int_reserved2(self, value):
        self.unsigned_int_reserved2 = value

    def deserialize(self, reader):
        super().deserialize(reader)
        self.relative_virtual_address_data_base = reader.parse_unsigned_int_val()
        self.virtual_address_image_base = reader.parse_unsigned_long_val()
        self.unsigned_int_reserved1 = reader.parse_unsigned_int_val()
        self.unsigned_int_reserved2 = reader.parse_unsigned_int_val()

    def dump(self):
        builder = StringBuilder("RvaVaDebugHeader--------------------------------------------\n")
        super().dumpInternal(builder)
        builder.append(f"relativeVirtualAddressDataBase: 0x{self.relative_virtual_address_data_base:x}\n")
        builder.append(
            f"virtualAddressImageBase: 0x{self.virtual_address_image_base:016X}\n"
        )
        builder.append(f"unsignedIntReserved1: 0x{self.unsigned_int_reserved1:08X}\n")
        builder.append(f"unsignedIntReserved2: 0x{self.unsigned_int_reserved2:08X}\n")
        return str(builder)

    def dumpInternal(self, builder):
        super().dumpInternal(builder)
        builder.append(
            f"relativeVirtualAddressDataBase: {self.relative_virtual_address_data_base:x}\n"
        )
        builder.append(
            f"virtualAddressImageBase: {self.virtual_address_image_base:016X}\n"
        )
        builder.append(f"unsignedIntReserved1: {self.unsigned_int_reserved1:08X}\n")
        builder.append(f"unsignedIntReserved2: {self.unsigned_int_reserved2:08X}\n")

class PdbByteReader:
    def parse_unsigned_int_val(self):
        # implement this method
        pass

    def parse_unsigned_long_val(self):
        # implement this method
        pass
```

Please note that the `PdbByteReader` class is not fully implemented in Python. You would need to add methods for parsing unsigned integer and long values based on your specific requirements.