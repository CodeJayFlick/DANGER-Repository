Here is the equivalent Python code:

```Python
class ImageSectionsOreoMR1:
    K_SECTION_OBJECTS = 0
    K_SECTION_ART_FIELDS = 1
    K_SECTION_ART_METHODS = 2
    K_SECTION_RUNTIME_METHODS = 3
    K_SECTION_IM_TABLES = 4
    K_SECTION_IMT_CONFLICT_TABLES = 5
    K_SECTION_DEX_CACHE_ARRAYS = 6
    K_SECTION_INTERNED_STRINGS = 7
    K_SECTION_CLASS_TABLE = 8
    K_SECTION_IMAGE_BITMAP = 9
    K_SECTION_COUNT = 10

    def __init__(self, reader, header):
        pass

    def get_k_section_objects(self):
        return self.K_SECTION_OBJECTS

    def get_k_section_art_fields(self):
        return self.K_SECTION_ART_FIELDS

    def get_k_section_art_methods(self):
        return self.K_SECTION_ART_METHODS

    def get_k_section_runtime_methods(self):
        return self.K_SECTION_RUNTIME_METHODS

    def get_k_section_im_tables(self):
        return self.K_SECTION_IM_TABLES

    def get_k_section_imt_conflict_tables(self):
        return self.K_SECTION_IMT_CONFLICT_TABLES

    def get_k_section_dex_cache_arrays(self):
        return self.K_SECTION_DEX_CACHE_ARRAYS

    def get_k_section_interned_strings(self):
        return self.K_SECTION_INTERNED_STRINGS

    def get_k_section_class_table(self):
        return self.K_SECTION_CLASS_TABLE

    def get_k_section_image_bitmap(self):
        return self.K_SECTION_IMAGE_BITMAP

    def get_k_section_count(self):
        return self.K_SECTION_COUNT
```

Note that the `UNSUPPORTED_SECTION` constant is not present in the original Java code, so I did not include it in this Python translation.