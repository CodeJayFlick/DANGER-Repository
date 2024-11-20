class AbstractAddressSpace:
    def __init__(self, name: str, size: int, unit_size: int, type: int):
        self.name = name
        self.size = size
        self.unit_size = unit_size
        self.type = type

        if (type == 0):  # TYPE_NONE
            self.min_address = self.max_address = self.getUncheckedAddress(0)
            self.space_id = -1
            return

        if unique < 0 or unique > Short.MAX_VALUE:
            raise ValueError("Unique space id must be between 0 and " + str(Short.MAX_VALUE) + " inclusive")

        self.name = name
        self.size = size
        self.unit_size = unit_size
        self.type = type

        if (bits_consumed_by_unit_size(unit_size) + size > 64):
            raise ValueError("Unsupported address space size (2^size * wordsize > 2^64)")

        if size != 64:
            self.space_size = ((long)(unit_size)) << size
            self.word_address_mask = (1L << size) - 1

    def bits_consumed_by_unit_size(self, unit_size: int):
        if unit_size < 1 or unit_size > 8:
            raise ValueError("Unsupported unit size: " + str(unit_size))

        cnt = 0
        for test in range(unit_size - 1, 0, -1):
            cnt += 1

        return cnt

    def has_signed_offset(self) -> bool:
        return self.signed

    # ... other methods ...

class AddressSpace(AbstractAddressSpace):
    pass
