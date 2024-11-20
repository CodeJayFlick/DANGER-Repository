Here is the equivalent Python code:

```Python
class OatMethodOffsetsKitKat:
    def __init__(self):
        self.frame_size_in_bytes = None
        self.core_spill_mask = None
        self.fp_spill_mask = None
        self.mapping_table_offset = None
        self.vmap_table_offset = None
        self.gc_map_offset = None

    def set_values(self, frame_size_in_bytes, core_spill_mask, fp_spill_mask,
                   mapping_table_offset, vmap_table_offset, gc_map_offset):
        self.frame_size_in_bytes = frame_size_in_bytes
        self.core_spill_mask = core_spill_mask
        self.fp_spill_mask = fp_spill_mask
        self.mapping_table_offset = mapping_table_offset
        self.vmap_table_offset = vmap_table_offset
        self.gc_map_offset = gc_map_offset

    def get_frame_size_in_bytes(self):
        return self.frame_size_in_bytes

    def get_core_spill_mask(self):
        return self.core_spill_mask

    def get_fp_spill_mask(self):
        return self.fp_spill_mask

    def get_mapping_table_offset(self):
        return self.mapping_table_offset

    def get_vmap_table_offset(self):
        return self.vmap_table_offset

    def get_gc_map_offset(self):
        return self.gc_map_offset
```

This Python code defines a class `OatMethodOffsetsKitKat` with methods to set and retrieve the values of various attributes. Note that there is no equivalent for Java's `BinaryReader` in this Python version, as it would require additional libraries or modules (like `struct`) to read binary data.