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
