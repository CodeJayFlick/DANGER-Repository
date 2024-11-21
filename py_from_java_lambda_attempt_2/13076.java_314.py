Here's your Java code translated into Python:

```Python
class ApplicationLayout:
    def __init__(self):
        self.application_properties = None
        self.application_root_dirs = []
        self.application_installation_dir = None
        self.modules = {}
        self.user_temp_dir = None
        self.user_cache_dir = None
        self.user_settings_dir = None
        self.patch_dir = None
        self.extension_archive_dir = None
        self.extension_installation_dirs = []

    def get_application_properties(self):
        return self.application_properties

    def get_application_root_dirs(self):
        return self.application_root_dirs

    def get_application_installation_dir(self):
        return self.application_installation_dir

    def get_modules(self):
        return self.modules

    def get_user_temp_dir(self):
        return self.user_temp_dir

    def get_user_cache_dir(self):
        return self.user_cache_dir

    def get_user_settings_dir(self):
        return self.user_settings_dir

    def get_extension_archive_dir(self):
        return self.extension_archive_dir

    def get_extension_installation_dirs(self):
        return self.extension_installation_dirs

    def get_patch_dir(self):
        return self.patch_dir

    def create_user_dirs(self):
        if self.user_temp_dir is not None:
            try:
                FileUtilities.mkdirs(self.user_temp_dir)
                os.chown(self.user_temp_dir, 0, 0)
            except Exception as e:
                raise IOException("Failed to create user temp directory: " + str(self.user_temp_dir))

        if self.user_cache_dir is not None:
            try:
                FileUtilities.mkdirs(self.user_cache_dir)
                os.chown(self.user_cache_dir, 0, 0)
            except Exception as e:
                raise IOException("Failed to create user cache directory: " + str(self.user_cache_dir))

        if self.user_settings_dir is not None:
            try:
                FileUtilities.mkdirs(self.user_settings_dir)
                os.chown(self.user_settings_dir, 0, 0)
            except Exception as e:
                raise IOException("Failed to create user settings directory: " + str(self.user_settings_dir))

    def in_single_jar_mode(self):
        return False
```

Please note that I've used Python's built-in `os` module for file operations and created a custom exception class named `IOException`.