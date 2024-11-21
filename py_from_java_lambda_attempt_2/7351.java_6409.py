Here is the translation of the Java code into Python:

```Python
class HFSPlusVolumeHeader:
    def __init__(self):
        self.signature = 0
        self.version = 4
        self.attributes = 0
        self.lastMountedVersion = 0
        self.journalInfoBlock = 0

        self.createDate = 0
        self.modifyDate = 0
        self.backupDate = 0
        self.checkedDate = 0

        self.fileCount = 0
        self.folderCount = 0

        self.blockSize = 4096
        self.totalBlocks = 0
        self.freeBlocks = 0

        self.nextAllocation = 0
        self.rsrcClumpSize = 0
        self.dataClumpSize = 0
        self.nextCatalogID = 0

        self.writeCount = 0
        self.encodingsBitmap = 0

        self.finderInfo = [0] * 8
        self.rawForkData = bytearray(400)

    @staticmethod
    def probe(provider):
        try:
            if len(provider) < 1024 + 512:
                return False
            header = HFSPlusVolumeHeader.read(provider)
            return header.isValid() and header.hasGoodVolumeInfo(provider)
        except Exception as e:
            return False

    @staticmethod
    def read(provider, offset=1024):
        reader = BinaryReader(provider, False)  # BE (Big Endian)
        reader.set_pointer_index(offset)

        result = HFSPlusVolumeHeader()
        result.signature = reader.read_next_short()
        result.version = reader.read_next_short()
        result.attributes = reader.read_next_int()
        result.lastMountedVersion = reader.read_next_int()
        result.journalInfoBlock = reader.read_next_int()

        result.createDate = reader.read_next_int()
        result.modifyDate = reader.read_next_int()
        result.backupDate = reader.read_next_int()
        result.checkedDate = reader.read_next_int()

        result.fileCount = reader.read_next_int()
        result.folderCount = reader.read_next_int()

        result.blockSize = reader.read_next_int()
        result.totalBlocks = reader.read_next_int()
        result.freeBlocks = reader.read_next_int()

        result.nextAllocation = reader.read_next_int()
        result.rsrcClumpSize = reader.read_next_int()
        result.dataClumpSize = reader.read_next_int()
        result.nextCatalogID = reader.read_next_int()

        result.writeCount = reader.read_next_int()
        result.encodingsBitmap = reader.read_next_longlong()

        result.finderInfo = reader.read_next_array(8, int)
        result.rawForkData = reader.read_next_bytearray(400)

        return result

    def isValid(self):
        return self.signature == 0x482b and self.version == 4 and is_good_block_size(self.blockSize)

    @staticmethod
    def is_good_block_size(bs):
        return bs > 0 and bs % 512 == 0

    def hasGoodVolumeInfo(self, provider):
        calculated_size = self.blockSize * self.totalBlocks
        # NOTE: can't compare with exact equals-to provider size because an extra 16 bytes are present in examples extracted from firmware images
        return len(provider) >= calculated_size


class BinaryReader:
    def __init__(self, provider, big_endian):
        self.provider = provider
        self.big_endian = big_endian

    def read_next_short(self):
        if self.big_endian:
            return int.from_bytes(self.provider.read(2), 'big')
        else:
            return int.from_bytes(self.provider.read(2), 'little')

    def read_next_int(self):
        if self.big_endian:
            return int.from_bytes(self.provider.read(4), 'big')
        else:
            return int.from_bytes(self.provider.read(4), 'little')

    def read_next_longlong(self):
        if self.big_endian:
            return int.from_bytes(self.provider.read(8), 'big')
        else:
            return int.from_bytes(self.provider.read(8), 'little')

    def read_next_array(self, length, dtype):
        result = []
        for _ in range(length):
            result.append(getattr(self, f'read_next_{dtype.__name__}'))
        return result

    def read_next_bytearray(self, size):
        return bytearray(self.provider.read(size))

    def set_pointer_index(self, offset):
        self.provider.seek(offset)
```

Note: Python does not have a direct equivalent to Java's `BinaryReader` class. The above code uses the built-in file operations and byte manipulation functions in Python to achieve similar functionality.