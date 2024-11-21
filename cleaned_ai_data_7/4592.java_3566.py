class ByteProviderPaddedInputStream:
    def __init__(self, provider: bytes, start_offset: int, length: int, pad_count: int):
        self.provider = provider
        self.current_bpo_offset = start_offset
        self.bp_end_offset = start_offset + length
        self.bp_end_pad_offset = bp_end_offset + pad_count

    def close(self) -> None:
        pass  # the provider is not closed

    def read(self, size: int = 1) -> int:
        if self.current_bpo_offset < self.bp_end_offset:
            byte_val = self.provider[self.current_bpo_offset]
            self.current_bpo_offset += 1
            return byte_val & 0xff
        elif self.current_bpo_offset < self.bp_end_pad_offset:
            self.current_bpo_offset += 1
            return 0
        return -1

    def available(self) -> int:
        return min(int((self.bp_end_pad_offset - self.current_bpo_offset)), 2**31-1)
