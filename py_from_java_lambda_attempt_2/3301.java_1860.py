Here is the translation of the Java code into Python:

```Python
class DataTypeArchiveMergeManagerPlugin:
    def __init__(self, tool, merge_manager, data_type_archive):
        super().__init__()
        self.tool = tool
        self.merge_manager = merge_manager
        self.data_type_archive = data_type_archive

    def create_provider(self):
        return MergeManagerProvider(self, f"Merge Data Type Archives for {data_type_archive.name}")

    def process_event(self, event):
        pass  # No equivalent in Python

    def dispose(self):
        provider.dispose()

    @staticmethod
    def get_description():
        return "Manage merge of Programs"

    @staticmethod
    def get_descriptive_name():
        return "Program Merge Manager"

    @staticmethod
    def get_category():
        return "Unmanaged"

    def get_merge_manager(self):
        return self.merge_manager

    def set_merge_component(self, component, component_id):
        provider.set_merge_component(component, component_id)

    def update_merge_description(self, merge_description):
        provider.update_merge_description(merge_description)

    def update_progress_details(self, progress_description):
        provider.update_progress_details(progress_description)

    def set_current_progress(self, current_percent_progress):
        provider.set_current_progress(current_percent_progress)

    def show_default_component(self):
        provider.show_default_component()

    def set_apply_enabled(self, state):
        provider.set_apply_enabled(state)

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, value):
        self._provider = value

    def close_all_programs(self, ignore_changes=False):
        return False  # No equivalent in Python

    def close_program(self):
        return False  # No equivalent in Python

    def close_program(self, program, ignore_changes=False):
        return False  # No equivalent in Python

    def get_all_open_data_type_archives(self):
        archive_merge_manager = self.merge_manager
        return [
            archive_merge_manager.get_data_type_archive(MergeConstants.RESULT),
            archive_merge_manager.get_data_type_archive(MergeConstants.LATEST),
            archive_merge_manager.get_data_type_archive(MergeConstants.MY),
            archive_merge_manager.get_data_type_archive(MergeConstants.ORIGINAL)
        ]

    def get_current_data_type_archive(self):
        return self.data_type_archive

    def get_program(self, addr):
        return None  # No equivalent in Python

    def get_search_priority(self, p):
        return 0  # No equivalent in Python

    def is_visible(self, program):
        return False  # No equivalent in Python

    def open_program(self, domain_file):
        return None  # No equivalent in Python

    def open_program(self, df, version):
        return None  # No equivalent in Python

    def open_program(self, df, version, state):
        return None  # No equivalent in Python

    def open_program(self, program):
        pass  # No equivalent in Python

    def open_program(self, program, current=False):
        pass  # No equivalent in Python

    def open_program(self, program, state):
        pass  # No equivalent in Python

    def release_program(self, program, persistent_owner):
        pass  # No equivalent in Python

    def set_current_program(self, p):
        pass  # No equivalent in Python

    def set_persistent_owner(self, program, owner):
        return False  # No equivalent in Python

    def set_search_priority(self, p, priority):
        pass  # No equivalent in Python
```

Note that some methods are not translated as they do not have a direct equivalent in Python.