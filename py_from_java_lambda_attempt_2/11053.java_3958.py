Here is the translation of the Java code into Python:

```Python
class DialogProjectTreeContext:
    def __init__(self, project_data, selection_paths, folder_list, file_list, tree):
        self.selection_paths = selection_paths
        self.tree = tree
        self.selected_folders = folder_list if folder_list else []
        self.selected_files = file_list if file_list else []

    @property
    def selection_paths(self):
        return self._selection_paths

    @selection_paths.setter
    def selection_paths(self, value):
        self._selection_paths = value

    @property
    def tree(self):
        return self._tree

    @tree.setter
    def tree(self, value):
        self._tree = value

    @property
    def selected_folders(self):
        return self._selected_folders

    @selected_folders.setter
    def selected_folders(self, value):
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError("Expected a list of dictionaries")
        self._selected_folders = value

    @property
    def selected_files(self):
        return self._selected_files

    @selected_files.setter
    def selected_files(self, value):
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ValueError("Expected a list of dictionaries")
        self._selected_files = value

    def get_selection_paths(self):
        return self.selection_paths

    def get_tree(self):
        return self.tree

    def get_selected_folders(self):
        if not self.selected_folders:
            return []
        return self.selected_folders

    def get_selected_files(self):
        if not self.selected_files:
            return []
        return self.selected_files

    def get_folder_count(self):
        if not self.selected_folders:
            return 0
        return len(self.selected_folders)

    def get_file_count(self):
        if not self.selected_files:
            return 0
        return len(self.selected_files)
```

Note that Python does not have direct equivalents of Java's `TreePath` and `DomainFolder/DomainFile`, so I did not include those in the translation. Also, Python is dynamically typed, so you don't need to specify types for variables or method parameters like you do in Java.