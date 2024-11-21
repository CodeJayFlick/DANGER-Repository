Here is the translation of the given Java code into Python:

```Python
class VarnodeData:
    def __init__(self):
        pass

    def __init__(self, base, off, size):
        self.space = base
        self.offset = off
        self.size = size

    def equals(self, obj):
        if obj == self:
            return True
        elif not isinstance(obj, VarnodeData):
            return False
        other = VarnodeData(obj)
        return (self.space == other.space) and (self.offset == other.offset) and (self.size == other.size)

    def __hash__(self):
        return hash((self.space.__hash__(), self.offset, self.size))

    def compareTo(self, other):
        result = self.space.compareTo(other.space)
        if result != 0:
            return result
        result = AddressUtils.unsignedCompare(self.offset, other.offset)
        if result != 0:
            return result
        return other.size - self.size

    def restore_xml(self, el, trans):
        name = el.getAttributeValue("name")
        if name is not None:
            vdata = trans.getRegister(name)
            self.space = vdata.space
            self.offset = vdata.offset
            self.size = vdata.size
            return

        attribute_value = el.getAttributeValue("space")
        if attribute_value is None:
            return

        self.space = trans.getSpaceByName(attribute_value)
        if self.space is None:
            raise LowlevelError(f"Unknown space name: {attribute_value}")
        self.offset = AddrSpace.restore_xml_offset(el)
        self.size = AddrSpace.restore_xml_size(el)

    def get_address(self):
        #if self.space == null:
         #   return Address(AddressSpace.MIN_SPACE, 0)
        return Address(self.space, self.offset)


class LowlevelError(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. Also, the translation is done in a way to maintain the same functionality as the original code.