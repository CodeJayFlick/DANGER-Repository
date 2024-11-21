Here is the translation of the Java code into equivalent Python:

```Python
import os
from urllib.parse import unquote
from collections import defaultdict

class GhidraJarApplicationLayout:
    def __init__(self):
        pass

    @property
    def in_single_jar_mode(self):
        return True

    def find_ghidra_application_root_dirs(self):
        app_prop_path = "/_Root/Ghidra/" + "ghidra.properties"
        root_dir = os.path.dirname(os.path.abspath(__file__))
        dirs = [os.path.join(root_dir, app_prop_path)]
        return dirs

    def find_ghidra_application_installation_dir(self):
        if not self.get_application_root_dirs():
            return None
        return os.path.dirname(self.get_application_root_dirs()[0])

    @property
    def get_application_root_dirs(self):
        return self.find_ghidra_application_root_dirs()

    def find_ghidra_modules(self):
        modules = defaultdict(dict)
        for root_dir in self.get_application_root_dirs():
            for dirpath, _, filenames in os.walk(root_dir):
                if any(filename.endswith(".jar") for filename in filenames):
                    module_name = os.path.basename(dirpath)
                    modules[module_name] = {}
        return dict(modules)

    def find_extension_archive_directory(self):
        return None

    @property
    def get_extension_installation_directories(self):
        extension_install_dir = os.path.dirname(os.path.abspath(__file__))
        return [os.path.join(extension_install_dir, "_Root/Ghidra/Extensions")]

    def from_url(self, url_string):
        try:
            decoded_url_string = unquote(url_string)
        except Exception as e:
            print(f"Failed to decode URL: {e}")
        return os.path.abspath(decoded_url_string)

# Usage
ghidra_layout = GhidraJarApplicationLayout()
print(ghidra_layout.in_single_jar_mode)  # prints True
```

Please note that Python does not have direct equivalent of Java's `ResourceFile` and `URLDecoder`. I've used the built-in Python modules to achieve similar functionality.