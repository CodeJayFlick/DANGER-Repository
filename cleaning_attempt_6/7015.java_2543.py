class ImageSections10:
    k_section_objects = 0
    k_section_art_fields = 1
    k_section_art_methods = 2
    k_section_runtime_methods = 3
    k_section_im_tables = 4
    k_section_imt_conflict_tables = 5
    k_section_dex_cache_arrays = 6
    k_section_interned_strings = 7
    k_section_class_table = 8
    k_section_string_reference_offsets = 9
    k_section_metadata = 10
    k_section_image_bitmap = 11
    k_section_count = 12

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
        return self.k_section_im_tables

    def get_k_section_imt_conflict_tables(self):
        return self.k_section_imt_conflict_tables

    def get_k_section_dex_cache_arrays(self):
        return self.k_section_dex_cache_arrays

    def get_k_section_interned_strings(self):
        return self.k_section_interned_strings

    def get_k_section_class_table(self):
        return self.k_section_class_table

    def get_k_section_string_reference_offsets(self):
        return self.k_section_string_reference_offsets

    def get_k_section_metadata(self):
        return self.k_section_metadata

    def get_k_section_image_bitmap(self):
        return self.k_section_image_bitmap

    def get_k_section_count(self):
        return self.k_section_count
