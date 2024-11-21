Here's your Java code translated into Python:

```Python
import os
from io import BufferedReader, FileIO
from textwrap import ParseException


class LaunchProperties:
    def __init__(self, file):
        self.file = file


class JavaConfig:
    LAUNCH_PROPERTIES_NAME = "launch.properties"
    JAVA_HOME_SAVE_NAME = "java_home.save"

    def __init__(self, install_dir):
        try:
            self.init_application_properties(install_dir)
            self.init_launch_properties(install_dir)
            self.init_java_home_save_file(install_dir)
        except (FileNotFoundError, IOError) as e:
            print(f"Error: {e}")

    @property
    def launch_properties(self):
        return self._launch_properties

    @property
    def min_supported_java(self):
        return self._min_supported_java

    @property
    def max_supported_java(self):
        return self._max_supported_java

    @property
    def compiler_compliance_level(self):
        return self._compiler_compliance_level

    @property
    def application_name(self):
        return self._application_name

    @property
    def application_version(self):
        return self._application_version

    @property
    def application_release_name(self):
        return self._application_release_name

    def get_launch_properties(self):
        return self.launch_properties

    def is_supported_java_home_dir(self, dir, java_filter):
        try:
            if not self.is_java_version_supported(get_java_version(dir, java_filter)):
                return False
        except (IOError, ParseException) as e:
            print(f"Error: {e}")
        return True

    def get_saved_java_home(self):
        try:
            with open(self.java_home_save_file, 'r') as f:
                line = f.readline().strip()
                if line and not line.isspace():
                    return File(line)
        except IOError as e:
            print(f"Error: {e}")
        return None

    def save_java_home(self, java_home_dir):
        try:
            with open(self.java_home_save_file, 'w') as f:
                f.write(str(java_home_dir))
        except IOError as e:
            print(f"Error: {e}")

    def get_java_version(self, dir, java_filter):
        if not os.path.exists(dir) or not os.path.isdir(dir):
            raise FileNotFoundError("Directory does not exist")

        bin_dir = os.path.join(dir, "bin")
        if not os.path.exists(bin_dir) or not os.path.isdir(bin_dir):
            raise FileNotFoundError("Missing bin directory")

        for f in os.listdir(bin_dir):
            file_path = os.path.join(bin_dir, f)
            if os.path.isfile(file_path):
                if f.lower() == "java" or f.lower().endswith(".exe"):
                    return run_and_get_java_version(FileIO.open(file_path, 'r'))
                elif java_filter == JavaFilter.JDK_ONLY and f.lower() == "javac":
                    raise FileNotFoundError("JDK is missing javac executable")
                elif java_filter == JavaFilter.JRE_ONLY and f.lower() != "javac":
                    raise FileNotFoundError("JRE should not have javac executable")

        return None

    def run_and_get_java_version(self, file):
        try:
            with BufferedReader(file) as reader:
                line = reader.readline().strip()
                if line.startswith("java.version ="):
                    version = line[14:]
                elif line.startswith("sun.arch.data.model ="):
                    arch = line[17:]

            return JavaVersion(version, arch)
        except (IOError, ParseException) as e:
            print(f"Error: {e}")

    def init_application_properties(self, install_dir):
        try:
            application_properties_file = os.path.join(install_dir, "Ghidra", "application.properties")
            if not os.path.exists(application_properties_file) or not os.path.isfile(application_properties_file):
                raise FileNotFoundError("Application properties file does not exist")

            with open(application_properties_file, 'r') as f:
                props = {}
                for line in f.readlines():
                    key_value_pair = line.strip().split("=")
                    if len(key_value_pair) == 2 and key_value_pair[0]:
                        props[key_value_pair[0].strip()] = key_value_pair[1].strip()

            self._application_name = props.get("application.name", "")
            self._application_version = props.get("application.version", "")
            self._application_release_name = props.get("application.release.name", "")

            try:
                min_supported_java = int(props["application.java.min"])
            except ValueError as e:
                raise ParseException(f"Failed to parse application's minimum supported Java major version: {e}")

            max_supported_java = 0
            if "application.java.max" in props and not props["application.java.max"].strip().isspace():
                try:
                    max_supported_java = int(props["application.java.max"])
                except ValueError as e:
                    raise ParseException(f"Failed to parse application's maximum supported Java major version: {e}")

        except (FileNotFoundError, IOError) as e:
            print(f"Error: {e}")

    def init_launch_properties(self, install_dir):
        try:
            launch_properties_file = os.path.join(install_dir, "Ghidra", "RuntimeScripts", "Common", self.LAUNCH_PROPERTIES_NAME)
            if not os.path.exists(launch_properties_file) or not os.path.isfile(launch_properties_file):
                raise FileNotFoundError("Launch properties file does not exist")

            with open(launch_properties_file, 'r') as f:
                props = {}
                for line in f.readlines():
                    key_value_pair = line.strip().split("=")
                    if len(key_value_pair) == 2 and key_value_pair[0]:
                        props[key_value_pair[0].strip()] = key_value_pair[1].strip()

            self._launch_properties = LaunchProperties(launch_properties_file)

        except (FileNotFoundError, IOError) as e:
            print(f"Error: {e}")

    def init_java_home_save_file(self, install_dir):
        try:
            user_home_dir_path = os.environ.get("USERPROFILE")
            if not user_home_dir_path or not user_home_dir_path.strip():
                raise FileNotFoundError("User home directory is not known.")

            user_home_dir = File(user_home_dir_path)
            if not user_home_dir.exists() or not user_home_dir.is_directory():
                raise FileNotFoundError(f"User home directory does not exist: {user_home_dir}")

            java_home_save_file_parent_dir = os.path.join(user_home_dir, "." + self._application_name.replace(" ", "").lower())
            user_settings_dir_name = f"{java_home_save_file_parent_dir}_{self._application_version}_{self._application_release_name.upper()}"
            if "DEV" in install_dir:
                user_settings_dir_name += "_location_" + os.path.dirname(install_dir).replace(os.sep, "/")

            java_home_save_file = File(os.path.join(user_settings_dir_name, self.JAVA_HOME_SAVE_NAME))
        except (FileNotFoundError) as e:
            print(f"Error: {e}")

    def get_defined_property(self, props, key):
        value = props.get(key)
        if not value or not value.strip():
            raise ParseException(f"Property '{key}' is not defined.")

        return value
```

Please note that Python does not have direct equivalent of Java's `File` class. Instead, you can use the built-in `os.path.join()` function to join path components together and create a file object using the `open()` function in read mode (`'r'`) or write mode (`'w'`).