import os

class ApplicationSettings:
    def __init__(self):
        pass

    @classmethod
    def get_user_application_settings_directory(cls):
        return cls().do_get_user_application_settings_directory()

    def do_get_user_application_settings_directory(self):
        return self._create_temp_dir("application.settings_")

    def _create_temp_dir(self, prefix):
        import tempfile
        tempdir = tempfile.mkdtemp(prefix=prefix)
        return os.path.join(tempdir)

# Register the ApplicationSettings class as a singleton instance.
ApplicationSettings_instance = ApplicationSettings()

def get_user_application_settings_directory():
    return ApplicationSettings().do_get_user_application_settings_directory()
