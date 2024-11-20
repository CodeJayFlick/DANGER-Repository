Here is the translation of the given Java code into Python:

```Python
class VendorBootImageHeaderFactory:
    @staticmethod
    def get_vendor_boot_image_header(provider: bytes, little_endian: bool = False) -> dict:
        return get_vendor_boot_image_header(BinaryReader(provider, little_endian))

    @staticmethod
    def get_vendor_boot_image_header(reader):
        if not BootImageUtil.is_vendor_boot_image(reader):
            raise ValueError("VendorBootImageHeader magic not found.")

        version = reader.read_int(BootImageConstants.VENDOR_BOOT_MAGIC_SIZE)

        match version:
            case 3:
                return VendorBootImageHeaderV3(reader)
            case 4:
                return VendorBootImageHeaderV4(reader)
            case _:
                raise ValueError(f"VendorBootImageHeader unsupported version found: {version}")

class BinaryReader:
    def __init__(self, provider: bytes, little_endian: bool):
        self.provider = provider
        self.little_endian = little_endian

    def read_int(self, size: int) -> int:
        # Implement your logic to read an integer from the byte array.
        pass


class BootImageUtil:
    @staticmethod
    def is_vendor_boot_image(reader: BinaryReader) -> bool:
        # Implement your logic to check if it's a vendor boot image header.
        pass


class VendorBootImageHeaderV3(BinaryReader):
    def __init__(self, reader: BinaryReader):
        super().__init__(reader.provider, reader.little_endian)


class VendorBootImageHeaderV4(BinaryReader):
    def __init__(self, reader: BinaryReader):
        super().__init__(reader.provider, reader.little_endian)
```

Please note that the Python code is not a direct translation of Java. The logic for reading integers from byte arrays and checking if it's a vendor boot image header are left to be implemented in their respective classes (`BinaryReader` and `BootImageUtil`).