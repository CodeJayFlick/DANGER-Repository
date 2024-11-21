Here is the translation of the given Java code into equivalent Python:

```Python
import io

class BootImageHeaderFactory:
    @staticmethod
    def get_boot_image_header(provider: bytes, little_endian: bool = False) -> dict:
        return get_boot_image_header(BinaryReader(provider, little_endian))

    @staticmethod
    def get_boot_image_header(reader):
        if not is_boot_image(reader):
            raise IOException("BootImageHeader magic not found.")

        version = reader.read_int(HEADER_VERSION_OFFSET)

        switcher = {
            0: lambda: BootImageHeaderV0(reader),
            1: lambda: BootImageHeaderV1(reader),
            2: lambda: BootImageHeaderV2(reader),
            3: lambda: BootImageHeaderV3(reader),
            4: lambda: BootImageHeaderV4(reader)
        }

        return switcher.get(version, lambda: raise IOException(f"BootImageHeader unsupported version found: {version}"))()


class BinaryReader:
    def __init__(self, provider: bytes, little_endian: bool = False):
        self.provider = provider
        self.little_endian = little_endian

    def read_int(self, offset) -> int:
        # implement your logic to read an integer from the byte array at given offset


def is_boot_image(reader: BinaryReader) -> bool:
    # implement your logic to check if a binary reader represents a boot image
```

Please note that Python does not have direct equivalent of Java's switch statement. We use dictionaries and lambda functions in this translation.

Also, we assume `BootImageHeaderV0`, `BootImageHeaderV1`, etc., are classes which take the BinaryReader as an argument to their constructor.