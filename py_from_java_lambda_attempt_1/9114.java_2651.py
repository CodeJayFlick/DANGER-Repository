Here is the translation of the Java code into Python:

```Python
class AddressMapTestDummy:
    def decode_address(self, value):
        return addr(value)

    def delete_overlay_space(self, name):
        raise RuntimeError("Unimplmented!")

    def find_key_range(self, key_ranges, address):
        raise RuntimeError("Unimplmented!")

    def get_absolute_encoding(self, address, create=False):
        raise RuntimeError("Unimplmented!")

    def get_address_factory(self):
        return None

    def get_image_base(self):
        raise RuntimeError("Unimplmented!")

    def get_key(self, address, create=False):
        return addr.get_offset()

    def get_key_ranges(self, start, end, create=False):
        key_ranges = []
        key_ranges.append(KeyRange(start.get_offset(), end.get_offset()))
        return key_ranges

    def get_key_ranges_set(self, set, create=False):
        raise RuntimeError("Unimplmented!")

    def get_key_ranges_absolute(self, start, end, create=False):
        raise RuntimeError("Unimplmented!")

    def get_mod_count(self):
        raise RuntimeError("Unimplmented!")

    def get_old_address_map(self):
        raise RuntimeError("Unimplmented!")

    def has_same_key_base(self, addr1, addr2):
        raise RuntimeError("Unimplmented!")

    def invalidate_cache(self):
        raise RuntimeError("Unimplmented!")

    def is_key_range_max(self, addr_key):
        raise RuntimeError("Unimplmented!")

    def is_key_range_min(self, addr_key):
        raise RuntimeError("Unimplmented!")

    def is_upgraded(self):
        raise RuntimeError("Unimplmented!")

    def rename_overlay_space(self, old_name, new_name):
        raise RuntimeError("Unimplmented!")

    def set_image_base(self, base):
        raise RuntimeError("Unimplmented!")
```

Note: The `addr` function and the classes like `KeyRange`, `AddressMap`, etc. are not defined in this code as they were part of the original Java class. You would need to define these or import them from another module for this Python code to work correctly.