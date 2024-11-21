Here is the translation of the Java code into Python:

```Python
class OMFSrcModuleFile:
    def __init__(self):
        self.cSeg = 0
        self.pad = 0
        self.baseSrcLn = []
        self.starts = []
        self.ends = []
        self.cbName = 0
        self.name = ""
        self.moduleLineList = []

    @staticmethod
    def create_OMFSrcModuleFile(reader, ptr):
        omf_src_module_file = OMFSrcModuleFile()
        omf_src_module_file.init_OMFSrcModuleFile(reader, ptr)
        return omf_src_module_file

    def init_OMFSrcModuleFile(self, reader, ptr):
        index = ptr
        self.cSeg = reader.read_short(index); index += 2
        self.pad = reader.read_short(index); index += 2

        self.baseSrcLn = [0] * (self.cSeg)
        for i in range(self.cSeg):
            self.baseSrcLn[i] = reader.read_int(index); index += 4
        self.starts = [0] * (self.cSeg)
        self.ends = [0] * (self.cSeg)

        for i in range(self.cSeg):
            self.starts[i] = reader.read_int(index); index += 4
            self.ends[i] = reader.read_int(index); index += 4

        self.cbName = reader.read_byte(index); index += 1
        self.name = reader.read_ascii_string(index, self.cbName); index += self.cbName

        for i in range(self.cSeg):
            line = OMFSrcModuleLine.create_OMFSrcModuleLine(reader, ptr + self.baseSrcLn[i])
            self.moduleLineList.append(line)
            index += line.get_byte_count()

    def get_OMFSrcModuleLines(self):
        return [x for x in self.moduleLineList]

    def get_base_src_ln(self):
        return self.baseSrcLn

    def get_segment_count(self):
        return self.cSeg

    def get_ends(self):
        return self.ends

    def get_name(self):
        return self.name

    def get_pad(self):
        return self.pad

    def get_starts(self):
        return self.starts


class OMFSrcModuleLine:
    @staticmethod
    def create_OMFSrcModuleLine(reader, ptr):
        # TO DO: implement this method
        pass

    def get_byte_count(self):
        # TO DO: implement this method
        pass
```

Please note that the `OMFSrcModuleLine` class is not fully implemented in Python as it was left incomplete in Java. You would need to add your own implementation for these methods based on how you want them to work.