Here is the translation of the given Java code into equivalent Python:

```Python
import os
import logging
from collections import OrderedDict

class ApplicationIdentifier:
    def __init__(self, application_properties):
        self.application_release_name = None
        for key, value in application_properties.items():
            if 'release.name' in key.lower():
                self.application_release_name = value

class GenericRunInfo:

    TEST_DIRECTORY_SUFFIX = "-Test"

    @staticmethod
    def get_user_settings_dirs_by_time():
        user_data_directory = Application.get_user_settings_directory()
        parent_dir = os.path.dirname(user_data_directory)

        app_dirs = collect_all_application_directories(parent_dir)
        
        modify_time_comparator = lambda f1, f2: (os.path.join(f1.name, Preferences.APPLICATION_PREFERENCES_FILENAME).mtime,
                                                     os.path.join(f2.name, Preferences.APPLICATION_PREFERENCES_FILENAME).mtime)[0] > [1][0]

        app_dirs.sort(key=modify_time_comparator)
        
        return app_dirs

    @staticmethod
    def collect_all_application_directories(data_directory_parent_dir):
        settings_dir_prefix = "." + Application.get_name().replace(" ", "").lower()
        user_dir_filter = lambda f: os.path.isdir(f) and f.name.startswith(settings_dir_prefix) and not f.name.endswith(GenericRunInfo.TEST_DIRECTORY_SUFFIX)

        data_dirs = [f for f in os.listdir(data_directory_parent_dir) if user_dir_filter(os.path.join(data_directory_parent_dir, f))]
        
        return data_dirs

    @staticmethod
    def get_previous_application_settings_file(filename):
        settings_dirs = GenericRunInfo.get_previous_application_settings_dirs_by_time()
        for dir in settings_dirs:
            alt_file_path = os.path.join(dir.name, filename)
            
            file = File(alt_file_path)
            if not file.exists():
                continue
            
            return file
        
        return None

    @staticmethod
    def get_previous_application_settings_dirs_by_time():
        my_identifier = ApplicationIdentifier(Application.get_application_layout().get_application_properties())
        my_release_name = my_identifier.application_release_name
        current_dir_name = Application.get_user_settings_directory().name

        settings_dirs = []

        for dir in GenericRunInfo.getUserSettingsDirsByTime():
            if dir.name == current_dir_name:
                continue
            
            try:
                identifier = ApplicationIdentifier(dir.name)
                release_name = identifier.application_release_name
                
                if release_name == my_release_name:
                    settings_dirs.append(dir)
                else:
                    logging.trace(f"Skipping {dir.name}")
            except Exception as e:
                logging(traceback.format_exc())
        
        return settings_dirs

    @staticmethod
    def get_projects_dir_path():
        path = Preferences.get_property(Preferences.PROJECT_DIRECTORY, None, True)

        if path and os.path.isdir(path):
            return path
        
        return os.environ['USERPROFILE']

    @staticmethod
    def set_projects_dir_path(path):
        if path and os.path.isdir(path):
            Preferences.set_property(Preferences.PROJECT_DIRECTORY, path)
```

Please note that Python does not have direct equivalent of Java's `Logger` class. It has a built-in logging module which can be used to log messages at different levels (DEBUG, INFO, WARNING, ERROR).