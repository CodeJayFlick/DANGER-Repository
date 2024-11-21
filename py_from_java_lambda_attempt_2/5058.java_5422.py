Here is the translation of the given Java interface into a Python class:

```Python
class Constants:
    # A 64-bit flag.
    IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

    # A 32-bit flag.
    IMAGE_ORDINAL_FLAG32 = 0x80000000

    # The magic number for PE files.
    IMAGE_NT_SIGNATURE = 0x00004550  # PE00
    # The magic number for OS/2 files.
    IMAGE_OS2_SIGNATURE = 0x454E  # NE
    # The magic number for little endian OS/2 files.
    IMAGE_OS2_SIGNATURE_LE = 0x454C  # LE
    # The magic number for VXD files.
    IMAGE_VXD_SIGNATURE = 0x454C  # LE

    # The 32-bit optional header magic number.
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
    # The 64-bit optional header magic number.
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    # The ROM optional header magic number.
    IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107

    # The size of the ROM optional header.
    SIZEOF_ROM_OPTIONAL_HEADER = 56
    # The size of the standard optional header.
    SIZEOF_STD_OPTIONAL_HEADER = 28
    # The size of the 32-bit optional header, in bytes.
    SIZEOF_NT_OPTIONAL32_HEADER = 224
    # The size of the 64-bit optional header, in bytes.
    SIZEOF_NT_OPTIONAL64_HEADER = 240

    # The size of the archive start header.
    ARCHIVE_START_SIZE = 8
    # The archive start magic value.
    ARCHIVE_START = "!<arch>\n"
    # The archive end magic value.
    ARCHIVE_END = "`\n"
    # The archive padding.
    ARCHIVE_PAD = "\n"
    # The archive linker member.
    ARCHIVE_LINKER_MEMBER = "/                "
    # The archive long names member.
    ARCHIVE_LONGNAMES_MEMBER = "//               "

# End of class
```

Please note that Python does not have direct equivalent to Java's interface. But the above code is a simple translation of your given Java interface into a Python class.