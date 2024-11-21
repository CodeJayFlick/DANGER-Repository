class DWARFImportOptions:
    DEFAULT_IMPORT_LIMIT_DIE_COUNT = 2000000
    DEFAULT_NAME_LENGTH_CUTOFF = None

    def __init__(self):
        self.output_dwarf_location_info = False
        self.output_die_info = False
        self.elide_typedefs_with_same_name = True
        self.import_data_types = True
        self.import_funcs = True
        self.import_limit_die_count = DWARFImportOptions.DEFAULT_IMPORT_LIMIT_DIE_COUNT
        self.name_length_cutoff = DEFAULT_NAME_LENGTH_CUTOFF

    def is_output_source_location_info(self):
        return self.output_dwarf_location_info

    def set_output_source_location_info(self, output_dwarf_location_info):
        self.output_dwarf_location_info = output_dwarf_location_info

    def is_output_die_info(self):
        return self.output_die_info

    def set_output_die_info(self, output_die_info):
        self.output_die_info = output_die_info

    def is_elide_typedefs_with_same_name(self):
        return self.elide_typedefs_with_same_name

    def set_elide_typedefs_with_same_name(self, elide_typedefs_with_same_name):
        self.elide_typedefs_with_same_name = elide_typedefs_with_same_name

    def is_import_data_types(self):
        return self.import_data_types

    def set_import_data_types(self, import_data_types):
        self.import_data_types = import_data_types

    def is_import_funcs(self):
        return self.import_funcs

    def set_import_funcs(self, output_func):
        self.import_funcs = output_func

    def get_import_limit_die_count(self):
        return self.import_limit_die_count

    def set_import_limit_die_count(self, import_limit_die_count):
        self.import_limit_die_count = import_limit_die_count

    def get_name_length_cutoff(self):
        return self.name_length_cutoff

    def set_name_length_cutoff(self, name_length_cutoff):
        self.name_length_cutoff = name_length_cutoff

    def is_preload_all_dies(self):
        return self.preload_all_dies

    def set_preload_all_dies(self, preload_all_dies):
        self.preload_all_dies = preload_all_dies

    def is_output_inline_func_comments(self):
        return self.output_inline_func_comments

    def set_output_inline_func_comments(self, output_inline_func_comments):
        self.output_inline_func_comments = output_inline_func_comments

    def is_output_lexical_block_comments(self):
        return self.output_lexical_block_comments

    def set_output_lexical_block_comments(self, output_lexical_block_comments):
        self.output_lexical_block_comments = output_lexical_block_comments

    def is_copy_rename_anon_types(self):
        return self.copy_rename_anon_types

    def set_copy_rename_anon_types(self, copy_rename_anon_types):
        self.copy_rename_anon_types = copy_rename_anon_types

    def is_create_func_signatures(self):
        return self.create_func_signatures

    def set_create_func_signatures(self, create_func_signatures):
        self.create_func_signatures = create_func_signatures

    def is_organize_types_by_source_file(self):
        return self.organize_types_by_source_file

    def set_organize_types_by_source_file(self, organize_types_by_source_file):
        self.organize_types_by_source_file = organize_types_by_source_file
