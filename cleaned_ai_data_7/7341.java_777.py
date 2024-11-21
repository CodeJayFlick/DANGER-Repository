import struct

class DyldCacheDylibExtractor:
    def extract_dylib(dylib_offset: int, provider: bytes, fsrl: str) -> bytes:
        # Make sure Mach-O header is valid
        mach_header = create_mach_header(provider, dylib_offset)
        mach_header.parse()

        packed_dylib = PackedDylib(mach_header, dylib_offset, provider)

        for cmd in mach_header.get_load_commands():
            if monitor.is_cancelled():
                break

            switch (cmd.get_command_type()):
                case LoadCommandTypes.LC_SEGMENT:
                    fixup_segment((SegmentCommand) cmd, packed_dylib, False, monitor)
                    break
                case LoadCommandTypes.LC_SEGMENTS_64:
                    fixup_segment((SegmentCommand) cmd, packed_dylib, True, monitor)
                    break
                # ... and so on

        return packed_dylib.get_byte_provider(fsrl)

    class PackedDylib:
        def __init__(self, mach_header: MachHeader, dylib_offset: int, provider: bytes):
            self.reader = BinaryReader(provider, True)
            self.packed_starts = {}
            size = 0
            for segment in mach_header.get_segments():
                packed_starts[segment] = size
                size += segment.get_file_size()

        def get_byte_provider(self) -> bytes:
            return bytearray(self.packed)

        def fixup(self, file_offset: int, size: int):
            if size not in [4, 8]:
                raise ValueError("Size must be 4 or 8")

            orig = self.reader.read_unsigned_value(file_offset, size)
            try:
                new_bytes = to_bytes(get_packed_offset(orig), size)
                self.packed[get_packed_offset(file_offset): get_packed_offset(file_offset) + len(new_bytes)] = list(new_bytes)
            except NotFoundException as e:
                print(f"Warning: {e}")

        def get_packed_offset(self, file_offset):
            for segment in packed_starts.keys():
                if file_offset >= segment.get_file_offset() and file_offset < segment.get_file_offset() + segment.get_file_size():
                    return file_offset - segment.get_file_offset() + self.packed_starts[segment]
            raise NotFoundException(f"Failed to convert DYLD file offset to packed DYLIB offset: {file_offset}")

        def to_bytes(self, value: int, size: int):
            if size not in [4, 8]:
                raise ValueError("Size must be 4 or 8")

            converter = LittleEndianDataConverter()
            return list(converter.get_bytes(value))[:size]

class BinaryReader:
    def __init__(self, provider: bytes, big_endian: bool):
        self.provider = provider
        self.big_endian = big_endian

    def read_unsigned_value(self, file_offset: int, size: int) -> int:
        if size not in [4, 8]:
            raise ValueError("Size must be 4 or 8")

        converter = LittleEndianDataConverter()
        return struct.unpack(f">I" if self.big_endian else f"<I", bytes([self.provider[file_offset + i] for i in range(size)]))[0]

class MachHeader:
    def __init__(self, provider: bytes):
        # ... and so on

    def parse(self) -> None:
        pass
