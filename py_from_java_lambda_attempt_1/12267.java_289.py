Here is the translation of the Java interface `DataType` into a Python class:

```Python
class DataType:
    def __init__(self):
        self.DEFAULT = None  # Singleton instance of default datatype.
        self.VOID = None      # Instance of void datatype (never use ==).
        self.CONFLICT_SUFFIX = ".conflict"
        self.NO_SOURCE_SYNC_TIME = 0L
        self.NO_LAST_CHANGE_TIME = 0L

    def has_language_dependent_length(self):
        pass  # To be implemented by subclasses.

    def get_settings_definitions(self):
        return []  # Default implementation returns an empty list of settings definitions.

    def get_default_settings(self):
        return None  # Default implementation returns None for default settings.

    def clone(self, dtm):
        raise NotImplementedError("This method must be implemented by the subclass.")

    def copy(self, dtm):
        raise NotImplementedError("This method must be implemented by the subclass.")

    def get_category_path(self):
        pass  # To be implemented by subclasses.

    def get_data_type_path(self):
        pass  # To be implemented by subclasses.

    def set_category_path(self, path):
        raise NotImplementedError("This method is not supported for this datatype.")

    def get_data_type_manager(self):
        return None  # Default implementation returns None for the data type manager.

    def get_display_name(self):
        pass  # To be implemented by subclasses.

    def get_name(self):
        pass  # To be implemented by subclasses.

    def get_path_name(self):
        pass  # To be implemented by subclasses.

    def set_name(self, name):
        raise NotImplementedError("This method is not supported for this datatype.")

    def get_mnemonic(self, settings=None):
        return None  # Default implementation returns None for the mnemonic.

    def get_length(self):
        pass  # To be implemented by subclasses.

    def is_zero_length(self):
        pass  # To be implemented by subclasses.

    def is_not_yet_defined(self):
        pass  # To be implemented by subclasses.

    def get_description(self):
        return None  # Default implementation returns None for the description.

    def set_description(self, description):
        raise NotImplementedError("This method is not supported for this datatype.")

    def get_docs(self):
        return None  # Default implementation returns None for documentation URL.

    def get_value(self, buf, settings=None, length=-1):
        pass  # To be implemented by subclasses.

    def is_encodable(self):
        return False  # Default implementation assumes the datatype cannot encode values.

    def encode_value(self, value, buf, settings=None, length=-1):
        raise NotImplementedError("This method must be implemented by the subclass.")

    def get_value_class(self, settings=None):
        pass  # To be implemented by subclasses.

    def is_deleted(self):
        return False  # Default implementation assumes the datatype has not been deleted.

    def is_equivalent(self, dt):
        return False  # Default implementation assumes the datatypes are not equivalent.

    def data_type_size_changed(self, dt):
        pass  # To be implemented by subclasses.

    def data_type_alignment_changed(self, dt):
        pass  # To be implemented by subclasses.

    def add_parent(self, dt):
        raise NotImplementedError("This method is reserved for internal use.")

    def remove_parent(self, dt):
        raise NotImplementedError("This method is reserved for internal use.")

    def get_parents(self):
        return []  # Default implementation returns an empty list of parents.

    def get_alignment(self):
        pass  # To be implemented by subclasses.

    def depends_on(self, dt):
        return False  # Default implementation assumes the datatype does not depend on another one.

    def set_source_archive(self, archive):
        self.source_archive = archive

    def get_source_archive(self):
        return None  # Default implementation returns None for source archive.

    def set_last_change_time(self, time):
        pass  # To be implemented by subclasses.

    def set_last_change_time_in_source_archive(self, time):
        pass  # To be implemented by subclasses.

    def get_universal_id(self):
        raise NotImplementedError("This method must be implemented by the subclass.")

    def replace_with(self, dt):
        raise NotImplementedError("This method is not supported for this datatype.")
```

Note that I've kept the Java-style comments and docstrings to help with understanding.