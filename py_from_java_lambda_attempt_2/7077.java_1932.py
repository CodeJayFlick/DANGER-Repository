Here is the translation of the given Java code into Python:

```Python
class VendorBootImageHeaderV3:
    def __init__(self):
        self.magic = None
        self.header_version = 0
        self.page_size = 0
        self.kernel_addr = 0
        self.ramdisk_addr = 0
        self.vendor_ramdisk_size = 0
        self.cmdline = ""
        self.tags_addr = 0
        self.name = ""
        self.header_size = 0
        self.dtb_size = 0
        self.dtb_addr = 0

    def get_magic(self):
        return self.magic

    def get_header_version(self):
        return self.header_version

    def get_page_size(self):
        return self.page_size

    def get_kernel_address(self):
        return self.kernel_addr

    def get_ramdisk_address(self):
        return self.ramdisk_addr

    def get_vendor_ramdisk_size(self):
        return self.vendor_ramdisk_size

    def get_cmdline(self):
        return self.cmdline

    def get_tags_address(self):
        return self.tags_addr

    def get_name(self):
        return self.name

    def get_header_size(self):
        return self.header_size

    def get_dtb_size(self):
        return self.dtb_size

    def get_dtb_address(self):
        return self.dtb_addr

    def get_dtb_offset(self, page_size):
        o = ((2112 + page_size - 1) // page_size)
        p = ((self.vendor_ramdisk_size + page_size - 1) // page_size)
        return (o + p) * page_size

class BootImageHeader:
    pass
```

Note: Python does not have direct equivalent of Java's `BinaryReader` and other classes used in the given code. The above translation is a simplified version, assuming that you will be reading the binary data separately using Python's built-in file handling functions or libraries like `struct`.