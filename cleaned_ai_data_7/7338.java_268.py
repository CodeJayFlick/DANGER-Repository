import struct

class DmgUtil:
    DMG_MAGIC_BYTES_v1 = b'\xd0\xcf$8\xb8'
    DMG_MAGIC_BYTES_v2 = b'FDSH'

    @staticmethod
    def is_dmg(program):
        if program is not None:
            address = program.min_address()
            if address is not None:
                try:
                    bytes_ = bytearray(8)
                    program.get_memory().get_bytes(address, bytes_)
                    return struct.pack('8B', *bytes_) in (DmgUtil.DMG_MAGIC_BYTES_v1, DmgUtil.DMG_MAGIC_BYTES_v2)
                except Exception:  # Catch all exceptions
                    pass
        return False

