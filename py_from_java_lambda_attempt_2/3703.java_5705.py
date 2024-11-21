Here is the translation of the Java code to Python:
```
import os
from tkinter import filedialog

class ArchiveFileChooser:
    def __init__(self):
        self.file_filter = ExtensionFileFilter(['ghidra_data_type_files'], 'Ghidra Data Type Files')
        self.approve_button_text = "Save As"
        self.approve_button_tooltip_text = "Save As"

    def prompt_user_for_file(self, suggested_filename):
        project_directory = os.path.join(os.environ['GHIDRA_PROJECTS_DIR'])
        last_opened_archive_path = Preferences.get('LAST_OPENED_ARCHIVE_DIRECTORY', None)
        if last_opened_archive_path:
            project_directory = last_opened_archive_path
        self.current_directory = project_directory

        suggested_name = f"{suggested_filename}{FileDataTypeManager.SUFFIX}"
        selected_file = os.path.join(project_directory, suggested_name)

        file = filedialog.askopenfilename(initialdir=project_directory, defaultname=suggested_name)
        if not file:
            return None
        fixed_file = self.fix_filename_suffix(file)
        Preferences.set('LAST_OPENED_ARCHIVE_DIRECTORY', os.path.dirname(fixed_file))
        Preferences.store()

        return fixed_file

    def fix_filename_suffix(self, file):
        filename = os.path.basename(file)
        if filename.endswith(FileDataTypeManager.SUFFIX):
            return file
        filename += FileDataTypeManager.SUFFIX
        return os.path.join(os.path.dirname(file), filename)

class ExtensionFileFilter:
    def __init__(self, extensions, description):
        self.extensions = extensions
        self.description = description

    def accept(self, f):
        for extension in self.extensions:
            if f.name.endswith(extension):
                return True
        return False

Preferences = None  # equivalent to Preferences class in Java
FileDataTypeManager = None  # equivalent to FileDataTypeManager class in Java
```
Note that I had to make some assumptions about the Python equivalents of certain classes and methods, as they are not directly translatable. For example, `GhidraFileChooser` is a custom component in Java, but there is no direct equivalent in Python's Tkinter library. Similarly, `Preferences` and `FileDataTypeManager` seem to be custom classes that manage preferences and file types respectively.

Also note that this code uses the `tkinter` library for GUI-related functionality (e.g., opening files), which may not be suitable for all use cases.