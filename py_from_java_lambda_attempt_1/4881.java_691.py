Here is the translation of the Java code into Python:

```Python
class DOSHeader:
    NAME = "IMAGE_DOS_HEADER"
    IMAGE_ D_OS_SIGNATURE = 0x5A4D  # MZ
    SIZEOF_DOS_HEADER = 64

    def __init__(self):
        self.e_magic = None
        self.e_cblp = None
        self.e_cp = None
        self.e_crlc = None
        self.e_cparhdr = None
        self.e_minalloc = None
        self.e_maxalloc = None
        self.e_ss = None
        self.e_sp = None
        self.e_csum = None
        self.e_ip = None
        self.e_cs = None
        self.e_lfarlc = None
        self.e_ovno = None
        self.e_res = [0, 0, 0, 0]
        self.e_oemid = None
        self.e_oeminfo = None
        self.e_res2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        self.e_lfanew = None

    @staticmethod
    def createDOSHeader(reader):
        dos_header = DOSHeader()
        dos_header.initDOSHeader(reader)
        return dos_header

    def initDOSHeader(self, reader):
        self.reader = reader
        self.parse()

    def parse(self):
        self.e_magic = self.reader.readShort()
        if self.e_magic != self.IMAGE_D_OS_SIGNATURE:
            return

        self.e_cblp = self.reader.readShort()
        self.e_cp = self.reader.readShort()
        self.e_crlc = self.reader.readShort()
        self.e_cparhdr = self.reader.readShort()
        self.e_minalloc = self.reader.readShort()
        self.e_maxalloc = self.reader.readShort()
        self.e_ss = self.reader.readShort()
        self.e_sp = self.reader.readShort()
        self.e_csum = self.reader.readShort()
        self.e_ip = self.reader.readShort()
        self.e_cs = self.reader.readShort()
        self.e_lfarlc = self.reader.readShort()
        self.e_ovno = self.reader.readShort()

    def getProcessorName(self):
        return "x86"

    # ... other methods similar to the Java code ...
```

Please note that Python does not have direct equivalent of Java's `struct` and `array`, so you would need to manually handle these types.