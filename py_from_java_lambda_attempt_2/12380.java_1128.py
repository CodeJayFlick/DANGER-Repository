Here is the translation of the given Java code into equivalent Python:

```Python
class SegmentedCodePointerDataType:
    def __init__(self):
        self.__name = "SegmentedCodeAddress"
        self.length = 4

    def get_mnemonic(self):
        return "segAddr"

    def get_description(self):
        return "Code address from 16 bit segment and 16 bit offset"

    def clone(self, dtm=None):
        if dtm is None:
            return self
        else:
            return SegmentedCodePointerDataType(dtm)

    def get_value(self, buf, settings, length=4):
        addr = buf.get_address()
        try:
            segment = buf.get_short(0) & 0xffff
            offset = buf.get_short(2) & 0xffff
            addr_value = (segment << 16) | offset
            return addr.new_address(addr_value, True)
        except Exception as ex:
            # Do nothing... Tried to form an address that was not readable or writeable.
            pass

    def get_representation(self, buf, settings):
        value = self.get_value(buf, settings)
        if value is None:
            return "??"
        else:
            return str(value)

# Example usage
buf = MemBuffer()  # Assuming this class exists in Python with the same functionality as Java's MemBuffer.
settings = Settings()
seg_addr_type = SegmentedCodePointerDataType()

print(seg_addr_type.get_mnemonic())  # Output: segAddr
print(seg_addr_type.get_description())  # Output: Code address from 16 bit segment and 16 bit offset

# Clone an instance of the class
new_seg_addr_type = seg_addr_type.clone()
```

Please note that Python does not have direct equivalent to Java's `@Override` annotation.