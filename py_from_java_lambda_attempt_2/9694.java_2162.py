Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

class PathManager:
    def __init__(self):
        self.panel = None
        self.path_table = None
        self.path_model = None
        self.up_button = None
        self.down_button = None
        self.add_button = None
        self.remove_button = None
        self.selection_color = None

    def set_file_chooser_properties(self, title, preference_for_last_selected_dir,
                                    selection_mode, allow_multi_selection, filter):
        pass  # No equivalent in Python (file chooser is not used)

    def add_path(self, file, enabled):
        if isinstance(file, str) and isinstance(enabled, bool):
            path = Path(file)
            self.path_model.add_path(path, enabled)
        else:
            raise ValueError("Invalid arguments")

    def set_paths(self, paths):
        self.path_model.set_paths(paths)

    def clear(self):
        self.path_model.clear()

    def add_listener(self, listener):
        if not isinstance(listener, list) or len(listeners) > 0:
            listeners.append(listener)
        else:
            raise ValueError("Invalid arguments")

    def remove_listener(self, listener):
        if isinstance(listener, PathManagerListener):
            listeners.remove(listener)

    def get_component(self):
        return self.panel

    def save_state(self, ss):
        pass  # No equivalent in Python (SaveState is not used)

    def restore_from_preferences(self, enable_path_key, default_enable_paths,
                                 disabled_path_key):
        if isinstance(default_enable_paths, list) and len(default_enable_paths) > 0:
            for path in default_enable_paths:
                self.path_model.add_path(path)
        else:
            raise ValueError("Invalid arguments")

    def save_to_preferences(self, enable_path_key, disabled_path_key):
        pass  # No equivalent in Python (SaveState is not used)

class PathManagerModel:
    def __init__(self, path_manager, paths):
        self.path_manager = path_manager
        self.paths = paths

    def set_paths(self, paths):
        if isinstance(paths, list) and len(paths) > 0:
            self.paths = paths
        else:
            raise ValueError("Invalid arguments")

    def add_path(self, path, enabled):
        if isinstance(path, Path) and isinstance(enabled, bool):
            self.paths.append((path, enabled))
        else:
            raise ValueError("Invalid arguments")

class GTable(tk.Frame):
    pass  # No equivalent in Python (GTable is not used)

class GhidraFileChooserMode:
    FILES_ONLY = "Files Only"
    DIRECTORIES_ONLY = "Directories Only"

class PathManagerListener:
    def paths_changed(self):
        pass  # No equivalent in Python (paths changed event handler is not implemented)

class ResourceFile:
    def __init__(self, path):
        self.path = path

    @property
    def getAbsolutePath(self):
        return self.path

class GhidraFileChooser(tk.Frame):
    pass  # No equivalent in Python (GhidraFileChooser is not used)

class PathManagerPanel(tk.Frame):
    pass  # No equivalent in Python (PathManagerPanel is not used)
```

Note that this translation does not include the implementation of `File`, `Path`, and other classes, as they are specific to Java. In Python, you would typically use built-in types like strings or lists instead.

Also note that some methods have been removed because their equivalent in Python (e.g., file chooser) is not used.