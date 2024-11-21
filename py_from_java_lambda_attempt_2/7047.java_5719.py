Here is the equivalent Python code:

```Python
class ImageSections_Nougat:
    k_section_objects = 0
    k_section_art_fields = 1
    k_section_art_methods = 2
    k_section_runtime_methods = 3
    k_section_imt_conflict_tables = 4
    k_section_dex_cache_arrays = 5
    k_section_interned_strings = 6
    k_section_class_table = 7
    k_section_image_bitmap = 8
    k_section_count = 9

    def __init__(self, reader, header):
        pass

    def get_k_section_objects(self):
        return self.k_section_objects

    def get_k_section_art_fields(self):
        return self.k_section_art_fields

    def get_k_section_art_methods(self):
        return self.k_section_art_methods

    def get_k_section_runtime_methods(self):
        return self.k_section_runtime_methods

    def get_k_section_im_tables(self):
        return "UNSUPPORTED_SECTION"

    def get_k_section_IMT_conflict_tables(self):
        return self.k_section_IMT_conflict_tables

    def get_k_section_dex_cache_arrays(self):
        return self.k_section_dex_cache_arrays

    def get_k_section_interned_strings(self):
        return self.k_section_interned_strings

    def get_k_section_class_table(self):
        return self.k_section_class_table

    def get_k_section_string_reference_offsets(self):
        return "UNSUPPORTED_SECTION"

    def get_k_section_metadata(self):
        return "UNSUPPORTED_SECTION"

    def get_k_section_image_bitmap(self):
        return self.k_section_image_bitmap

    def get_k_section_count(self):
        return self.k_section_count
```

Note that Python does not have direct equivalent of Java's `public` and `static`. In this code, I did not include the `public` keyword as it is implied by default in Python. Also, there are no explicit access modifiers like `private`, `protected`, etc., but you can achieve similar functionality using underscore prefix for variables or methods that should be treated as private.