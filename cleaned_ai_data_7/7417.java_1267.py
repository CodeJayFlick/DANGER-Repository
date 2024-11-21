class LzssUtil:
    @staticmethod
    def is_lzss(program):
        if program is not None:
            min_address = program.min_address()
            if min_address is not None:
                compression_bytes = get_bytes(program, min_address)
                if compression_bytes == LzssConstants.SIGNATURE_COMPRESSION_BYTES:
                    format_bytes = get_bytes(program, min_address + len(compression_bytes))
                    if format_bytes == LzssConstants.SIGNATURE_LZSS_BYTES:
                        return True
        return False

    @staticmethod
    def get_bytes(program, address):
        bytes = bytearray(4)
        try:
            program.get_memory().get_bytes(address, bytes)
        except Exception as e:  # Python doesn't have a specific MemoryAccessException like Java does.
            pass
        return bytes


# Assuming LzssConstants is defined elsewhere in your codebase. If not, you can replace it with the actual values.
LzssConstants = {
    'SIGNATURE_COMPRESSION_BYTES': bytearray([0x78, 0x9c]),
    'SIGNATURE_LZSS_BYTES': bytearray([0x5a, 0x4f])
}
