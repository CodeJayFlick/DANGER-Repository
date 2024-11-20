Here is the translation of the given Java code into equivalent Python:

```Python
class VendorBootImageHeader:
    def __init__(self):
        pass

    def get_magic(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_vendor_ramdisk_offset(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_vendor_ramdisk_size(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_dtb_offset(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_dtb_size(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")
```

In Python, we don't have direct equivalent of Java's abstract classes and methods. However, the above code is a common pattern used to implement interfaces or abstract base classes in Python. The `get_magic`, `get_vendor_ramdisk_offset`, etc., are placeholders for actual implementation which should be provided by any subclass that inherits from this class.