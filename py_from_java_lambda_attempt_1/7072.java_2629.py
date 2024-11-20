Here is the translation of the given Java code into equivalent Python:

```Python
import struct

class BootImageUtil:
    @staticmethod
    def is_boot_image(program):
        try:
            bytes = program.get_memory().get_bytes(program.get_min_address(), 16)
            return bytes == b'ANDROID\0SYSTEM\0'
        except Exception as e:
            # ignore exceptions
            pass
        return False

    @staticmethod
    def is_vendor_boot_image(program):
        try:
            bytes = program.get_memory().get_bytes(program.get_min_address(), 8)
            return bytes == b'VENDORBOOT'
        except Exception as e:
            # ignore exceptions
            pass
        return False

    @staticmethod
    def get_os_version_string(os_version):
        a = (os_version & 0xfe000000) >> 25
        b = (os_version & 0x01fc0000) >> 18
        c = (os_version & 0x0003f800) >> 11
        y = (os_version & 0x000007f0) >> 4
        m = os_version & 0x0000000f

        return f"{a}.{b}.{c}_{y}_{m}"
```

Please note that the Python code does not exactly replicate the Java code. It is an equivalent translation, but with some differences in syntax and functionality.