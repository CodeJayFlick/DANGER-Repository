Here is the translation of the given Java code into equivalent Python:

```Python
import io
from typing import List

class VendorBootImageFileSystem:
    def __init__(self, file_system_name: str, provider):
        self.file_system_name = file_system_name
        self.provider = provider
        self.header = None
        self.ramdisk_file = None
        self.dtb_file = None
        self.file_list = []

    @property
    def root(self) -> 'GFile':
        return GFile()

    def is_valid(self, monitor):
        bytes = self.provider.read_bytes(0, BootImageConstants.VENDOR_BOOT_MAGIC_SIZE)
        return bytes == BootImageConstants.VENDOR_BOOT_MAGIC.encode('utf-8')

    def open(self, monitor):
        if not self.header:
            self.header = VendorBootImageHeaderFactory.get_vendor_boot_image_header(self.provider, True)

        if self.header.magic != BootImageConstants.VENDOR_BOOT_MAGIC:
            raise io.IOException("Invalid Android boot image file!")

        if self.header.vendor_ramdisk_size > 0:
            ramdisk_file = GFile.from_filename(self.root, 'ramdisk', False,
                                               self.header.vendor_ramdisk_size)
            self.file_list.append(ramdisk_file)

        if self.header.dtb_size > 0:
            dtb_file = GFile.from_filename(self.root, 'dtb', False,
                                           self.header.dtb_size)
            self.file_list.append(dtb_file)

    def close(self):
        self.ramdisk_file = None
        self.dtb_file = None
        self.header = None

    def get_listing(self, directory) -> List['GFile']:
        if not directory or directory == self.root:
            return [file for file in self.file_list]
        else:
            return []

    def get_file_attributes(self, file: 'GFile', monitor):
        if file == self.ramdisk_file:
            return FileAttributes(comment='This is a ramdisk, it is a GZIP file containing a CPIO archive.')
        elif file == self.dtb_file:
            return FileAttributes(comment='This is a DTB file. It appears unused at this time.')
        else:
            return None

    def get_byte_provider(self, file: 'GFile', monitor) -> io.ByteProvider:
        if file == self.ramdisk_file:
            return ByteProviderWrapper(self.provider,
                                        self.header.vendor_ramdisk_offset,
                                        int(self.header.vendor_ramdisk_size),
                                        file.fsrl)
        elif file == self.dtb_file:
            return ByteProviderWrapper(self.provider,
                                        self.header.dtb_offset,
                                        int(self.header.dtb_size),
                                        file.fsrl)
        else:
            return None

class GFile:
    def __init__(self):
        pass

    @property
    def fsrl(self) -> str:
        return ''

    @staticmethod
    def from_filename(root, name, is_directory=False, size=None):
        return GFile()

class FileAttributes:
    def __init__(self, comment=''):
        self.comment = comment

    @classmethod
    def of(cls, attribute):
        return cls(attribute)

    @property
    def comment(self) -> str:
        return self.comment
```

Note that Python does not have direct equivalent to Java's `@FileSystemInfo` annotation. Also, Python does not support operator overloading like Java does with the `==` operator in the `isValid()` method.