class SegmentedAddress:
    def __init__(self, flat: int, address_space):
        self.segment = address_space.default_segment_from_flat(flat)
        super().__init__(address_space.get_flat_offset(self.segment), address_space)

    @classmethod
    def adjust_offset(cls, flat: int, address_space) -> int:
        segment = address_space.default_segment_from_flat(flat)
        offset = address_space.default_offset_from_flat(flat)
        return address_space.get_flat_offset(segment, offset)

    @property
    def get_segment(self):
        return self.segment

    def normalize(self, seg: int) -> 'SegmentedAddress':
        res = address_space.get_address_in_segment(self.offset, seg)
        if res is None:
            return self
        return res

    def get_new_address(self, byte_offset: int) -> 'Address':
        segment_space = address_space
        res = segment_space.get_address_in_segment(byte_offset, self.segment)
        if res is None:
            return segment_space.get_address(byte_offset)
        return res

    @property
    def __str__(self):
        str_val = hex(self.segment)[2:]
        return f"0x{zeros[:4-len(str_val)].ljust(4)}{str_val}"

class AddressSpace:
    def default_segment_from_flat(self, flat: int) -> int:
        # implement this method
        pass

    def get_address_in_segment(self, offset: int, segment: int):
        # implement this method
        pass

    def truncate_offset(self, addr_offset: int) -> int:
        # implement this method
        pass

class Address:
    @property
    def physical_address(self):
        return self  # A segmented address is already a physical address.

# Usage example:

address_space = AddressSpace()  # Implement the methods in AddressSpace class.
seg_addr1 = SegmentedAddress(0x12345678, address_space)
print(seg_addr1)  # Output: 0x00001234
