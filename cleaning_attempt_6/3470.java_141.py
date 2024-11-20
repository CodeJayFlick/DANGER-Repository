class BasicChecksumAlgorithm:
    def __init__(self, size):
        self.size = size
        if isinstance(size, int):
            self.num_bytes = size
        else:
            self.num_bytes = size.get_num_bytes()
        super().__init__("Checksum-" + str(self.num_bytes * 8))

    def update_checksum(self, memory, addr_set, monitor=None, xor=False, carry=False, ones_comp=False, twos_comp=False):
        if monitor and monitor.is_cancelled():
            raise CancelledException()

        sum = 0
        for byte in MemoryByteIterator(memory, addr_set):
            b = byte & 0xFF
            next_byte = (self.size == SupportedByteSize.CHECKSUM8) or (b << ((self.num_bytes - 1) - i % self.num_bytes * 8))
            if xor:
                sum ^= next_byte
            else:
                sum += next_byte
            i += 1

        # Handle carry
        if carry:
            max = pow(2, self.num_bytes * 8)
            while sum >= max:
                sum = (sum & (max - 1)) + (sum >> (self.num_bytes * 8))

        # Handle complement
        if ones_comp:
            sum = ~sum
        elif twos_comp:
            sum = -sum

        self.checksum = to_array(sum, self.num_bytes)

    def supports_decimal(self):
        return True


class SupportedByteSize:
    CHECKSUM8 = (1,)
    CHECKSUM16 = (2,)
    CHECKSUM32 = (4,)


def MemoryByteIterator(memory, addr_set):
    # This is a placeholder for the actual implementation
    pass


def to_array(sum, num_bytes):
    # This is a placeholder for the actual implementation
    pass

class CancelledException(Exception):
    pass
