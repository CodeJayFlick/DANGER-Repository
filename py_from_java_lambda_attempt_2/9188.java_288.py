Here is the translation of the Java code into Python:

```Python
class RecoveryFile:
    def __init__(self, src_bf, rfile, create=False):
        self.read_only = not create
        if create:
            self.index_count = src_bf.get_index_count()
            self.recovery_file = LocalBufferFile(rfile, src_bf.get_buffer_size())
            # Save magic number for version file
            self.recovery_file.set_parameter("VersionFile", 0x38DE7654)
            # Mark as invalid
            self.recovery_file.set_parameter("OrigBufCnt", -1)
            # Save original and source file ID as user parameter values
            src_id = src_bf.get_file_id()
            self.recovery_file.set_parameter("SrcIdHi", (src_id >> 32))
            self.recovery_file.set_parameter("SrcIdLow", (src_id & 0xffffffffL))
        else:
            self.recovery_file = LocalBufferFile(rfile, True)
            self.read_only = True
            # Parse file
            if not self.parse_file():
                raise Exception("Invalid recovery file")

    def parse_file(self):
        try:
            timestamp = (self.recovery_file.get_parameter(0x38DE7654) >> 32) | (self.recovery_file.get_parameter(0xffffffffL) & 0xffffffffL)
        except NoSuchElementException:
            # Not as good - better than nothing
            timestamp = self.recovery_file.get_last_modified()
        src_id = ((self.recovery_file.get_parameter("SrcIdHi") << 32) | (self.recovery_file.get_parameter("SrcIdLow") & 0xffffffffL))
        index_count = self.recovery_file.get_parameter("BufferCount")
        # Read buffer map
        if not self.read_buffer_map():
            raise Exception("Corrupt recovery file")

    def read_buffer_map(self):
        try:
            for _ in range(index_count):
                pass
        except NoSuchElementException as e:
            return False

    def save_buffer_map(self, buf):
        max_offset = (buf.get_size() - 8) & ~0x07
        offset = 4
        while True:
            if offset > max_offset:
                # Get next map buffer
                this_index = buf.get_int(offset)
                self.recovery_file.put(buf, this_index)
                break
            # Read map entry - end of list signified by -1
            real_index = buf.get_int(offset)
            if real_index < 0:
                return
            offset += 4

    def set_modified(self):
        pass

    def close(self):
        self.recovery_file.close()
        self.recovery_file = None

    # ... other methods ...
```

Note that this is a direct translation of the Java code into Python, and may not be idiomatic or efficient Python.