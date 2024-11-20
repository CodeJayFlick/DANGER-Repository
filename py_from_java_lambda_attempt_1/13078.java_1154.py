Here is the translation of the Java code into equivalent Python:

```Python
import os
from collections import defaultdict

class ApplicationUtilities:
    def find_default_application_root_dirs(self):
        application_root_dirs = []
        primary_app_dir = self.find_primary_application_root_dir()
        if primary_app_dir:
            application_root_dirs.append(primary_app_dir)
            if SystemUtilities.is_in_testing_mode() or SystemUtilities.is_in_development_mode():
                application_root_dirs.extend(
                    self.find_application_root_dirs_from_repo_config(primary_app_dir))
        return application_root_dirs

    def find_primary_application_root_dir(self):
        classpath = os.environ['CLASSPATH'].split(os.pathsep)
        for path_entry in classpath:
            try:
                path_file = ResourceFile(path_entry, False)
                while path_file and path_file.exists():
                    app_properties_file = ResourceFile(
                        path_file, ApplicationProperties.PROPERTY_FILE)
                    if self.validate_application_properties_file(app_properties_file):
                        return path_file
                    path_file = path_file.parent
            except Exception as e:
                Msg.error(ApplicationUtilities.__name__, f"Invalid class path entry: {path_entry}", e)
        return None

    def validate_application_properties_file(self, application_properties_file):
        if application_properties_file.exists():
            try:
                app_properties = ApplicationProperties(application_properties_file)
                if not app_properties.application_name.empty:
                    return True
            except Exception as e:
                Msg.error(ApplicationUtilities.__name__, f"Failed to read: {application_properties_file}", e)
        return False

    def find_application_root_dirs_from_repo_config(self, primary_app_dir):
        repo_config_file = ResourceFile(primary_app_dir.parent, "ghidra.repos.config")
        if repo_config_file.exists():
            try:
                with open(repo_config_file.path) as reader:
                    for line in reader.readlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        potential_app_root_dir = ResourceFile(
                            repo_config_file.parent, f"{line}{os.sep}Ghidra")
                        if potential_app_root_dir.exists() and potential_app_root_dir.is_directory:
                            return [potential_app_root_dir]
            except Exception as e:
                Msg.error(ApplicationUtilities.__name__, "Failed to read: ", repo_config_file)
        return []

    def get_default_user_temp_dir(self, application_properties):
        tmpdir = os.environ.get("TMPDIR")
        if not tmpdir or not tmpdir.strip():
            raise FileNotFoundError(
                f"System property 'TMPDIR' is not set!")
        return File(os.path.join(tmpdir, f"{os.getlogin()}-{application_properties.application_name}"))

    def get_default_user_cache_dir(self, application_properties):
        cachedir = os.environ.get("APPLICATION_CACHEDIR", "").strip()
        if cachedir:
            return self.get_default_user_temp_dir(application_properties)
        # Handle Windows specially
        if SystemUtilities.CURRENT_OPERATING_SYSTEM == SystemUtilities.WINDOWS:
            local_app_data_dir_path = os.environ.get("LOCALAPPDATA")
            if local_app_data_dir_path and not local_app_data_dir_path.strip():
                user_home = os.environ.get("USERPROFILE")
                if user_home:
                    return File(os.path.join(user_home, "AppData\\Local"))
        # Use user temp directory
        return self.get_default_user_temp_dir(application_properties)

    def get_default_user_settings_dir(self, application_properties, installation_directory):
        homedir = os.environ.get("HOME", "").strip()
        if not homedir or not homedir.strip():
            raise FileNotFoundError(f"System property 'USERPROFILE' is not set!")
        app_identifier = ApplicationIdentifier(application_properties)
        user_settings_parent_dir = File(os.path.join(homedir, f".{app_identifier.application_name}"))
        user_settings_dir_name = f".{app_identifier}"
        if SystemUtilities.is_in_development_mode():
            # Add the application's installation directory name to this variable
            user_settings_dir_name += "_location_" + installation_directory.name
        return File(os.path.join(user_settings_parent_dir, user_settings_dir_name))
```

Please note that Python does not have direct equivalent of Java concepts like `ResourceFile`, `ApplicationProperties` and `SystemUtilities`. You would need to implement these classes or functions in your own code.