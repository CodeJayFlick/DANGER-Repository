Here is the translation of the Java code into Python:

```Python
import os
from collections import defaultdict
from typing import Dict, List, Tuple

class ModuleUtilities:
    BINARY_PATH = "bin/main"
    MANIFEST_FILE_NAME = "Module.manifest"
    MANIFEST_FILE_NAME_UNINSTALLED = "Module.manifest.uninstalled"
    MODULE_LIST = "MODULE_LIST"

    MAX_MODULE_DEPTH = 3

    def is_module_directory(self, dir: str) -> bool:
        return os.path.exists(os.path.join(dir, self.MANIFEST_FILE_NAME))

    @staticmethod
    def find_module_root_directories(root_dir: str, module_root_dirs: List[str]) -> Dict[str, str]:
        for root, dirs, files in os.walk(root_dir):
            if "build" in dirs:
                continue
            for dir in dirs:
                if ModuleUtilities.is_module_directory(os.path.join(root, dir)):
                    module_root_dirs.append(dir)
                else:
                    find_module_root_directories(os.path.join(root, dir), module_root_dirs)

        return dict(zip(module_root_dirs, [os.path.join(root_dir, d) for d in module_root_dirs]))

    @staticmethod
    def get_module_lib_directories(modules: Dict[str, str]) -> List[Tuple]:
        library_directories = []
        for module, path in modules.items():
            if os.path.exists(os.path.join(path, "lib")):
                library_directories.append((module, os.path.join(path, "lib")))
            elif SystemUtilities.is_in_testing_mode():
                if os.path.exists(os.path.join(path, "libs")):
                    library_directories.append((module, os.path.join(path, "libs")))

        return library_directories

    @staticmethod
    def get_module_bin_directories(modules: Dict[str, str]) -> List[Tuple]:
        binary_path_tokens = ModuleUtilities.BINARY_PATH.split(":")
        bin_directories = []
        for module, path in modules.items():
            for token in binary_path_tokens:
                if os.path.exists(os.path.join(path, token)):
                    bin_directories.append((module, os.path.join(path, token)))

        return bin_directories

    @staticmethod
    def is_in_module(path_name: str) -> bool:
        module = ModuleUtilities.get_module(path_name)
        return module != None and os.path.dirname(module)

    @staticmethod
    def get_module(path_name: str) -> str:
        path = os.path.normpath(path_name)
        while True:
            if ModuleUtilities.is_module_directory(path):
                return path
            path = os.path.dirname(path)
            if not path or path == "/":
                break

        return None

    @staticmethod
    def find_repo_root(f: str) -> str:
        repo_dir = f
        while True:
            if os.path.exists(os.path.join(repo_dir, ".git")):
                return repo_dir
            parent = os.path.dirname(repo_dir)
            if not parent or parent == "/":
                break

        return None

    @staticmethod
    def find_repo(f: str) -> str:
        test_git = f + "/.git"
        if os.path.exists(test_git):
            return f
        else:
            return ModuleUtilities.find_repo(os.path.dirname(f))

    @staticmethod
    def is_external_module(module, layout):
        module_root_dir = module.getModuleRoot().getFile(False)
        for dir in layout.getApplicationRootDirs():
            parent_file = dir.getParentFile()
            if FileUtilities.isPathContainedWithin(parent_file.getFile(False), module_root_dir):
                return True

        return False
```

Note that this translation is not a direct conversion from Java to Python, but rather an interpretation of the original code. The logic and functionality are preserved as much as possible, while adapting it to work in a Python environment.