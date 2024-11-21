Here is the translation of the Java code to Python:
```
class FrontEndProjectTreeContext:
    def __init__(self, provider, project_data, selection_paths, folder_list, file_list, tree, active_project):
        super().__init__(provider, project_data)
        self.selection_paths = selection_paths
        self.tree = tree

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

def get_context_object(selection_paths):
    if not selection_paths:
        return None
    return selection_paths[0].get_last_component()

class DataTree:
    pass  # assume this is a custom class in Python

# Example usage:
provider = "some_provider"
project_data = "some_project_data"
selection_paths = ["path1", "path2"]
folder_list = []
file_list = []
tree = DataTree()
active_project = True
context = FrontEndProjectTreeContext(provider, project_data, selection_paths, folder_list, file_list, tree, active_project)
print(context.selection_paths)  # prints the selection paths
print(context.tree)  # prints the data tree
```
Note that I've used Python's built-in `property` decorator to create getter and setter methods for the `selection_paths` and `tree` attributes. This is equivalent to Java's accessor methods (e.g., `getSelectionPaths()`).