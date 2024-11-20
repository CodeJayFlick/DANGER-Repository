Here is the translation of the given Java code into Python:

```Python
class Ext4MMP:
    def __init__(self, provider):
        self.mmp_magic = 0
        self.mmp_seq = 0
        self.mmp_time = 0
        self.mmp_nodename = bytearray(64)
        self.mmp_bdevname = bytearray(32)
        self.mmp_check_interval = 0
        self.mmp_pad1 = 0
        self.mmp_pad2 = [0] * 226
        self.mmp_checksum = 0

    def from_binary_reader(self, reader):
        self.mmp_magic = int.from_bytes(reader.read(4), 'little')
        self.mmp_seq = int.from_bytes(reader.read(4), 'little')
        self.mmp_time = int.from_bytes(reader.read(8), 'little')
        self.mmp_nodename = bytearray(reader.read(64))
        self.mmp_bdevname = bytearray(reader.read(32))
        self.mmp_check_interval = int.from_bytes(reader.read(2), 'little', signed=True)
        self.mmp_pad1 = int.from_bytes(reader.read(2), 'little', signed=True)
        self.mmp_pad2 = [int.from_bytes(reader.read(4), 'little') for _ in range(226)]
        self.mmp_checksum = int.from_bytes(reader.read(4), 'little')

    def get_mmp_magic(self):
        return self.mmp_magic

    def get_mmp_seq(self):
        return self.mmp_seq

    def get_mmp_time(self):
        return self.mmp_time

    def get_mmp_nodename(self):
        return bytes(self.mmp_nodename)

    def get_mmp_bdevname(self):
        return bytes(self.mmp_bdevname)

    def get_mmp_check_interval(self):
        return self.mmp_check_interval

    def get_mmp_pad1(self):
        return self.mmp_pad1

    def get_mmp_pad2(self):
        return self.mmp_pad2

    def get_mmp_checksum(self):
        return self.mmp_checksum
```

Note: The `toDataType` method in the Java code is not directly translatable to Python, as it seems to be related to a specific framework or library (Ghidra) that is not available for Python.