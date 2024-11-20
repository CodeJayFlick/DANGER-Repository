Here is the translation of the Java code into Python:

```Python
import os
from tkinter import filedialog
from tkinter import messagebox

class OpenArchiveAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Open File Data Type Archive", plugin.name)
        set_menu_bar_data(["Open File Archive...", "Archive"])
        description("Opens a data type archive in this data type manager.")
        enabled(True)

    def actionPerformed(self, context):
        provider = self.plugin.get_provider()
        tree = provider.get_tree()
        file_chooser = GhidraFileChooser(tree)

        archive_directory = get_archive_directory()

        file_chooser.set_file_filter(ExtensionFileFilter([".ghdt"], "Ghidra Data Type Files"))
        file_chooser.set_current_directory(archive_directory)
        file_chooser.set_approve_button_text("Open DataType Archive File")
        file_chooser.set_approve_button_tooltip_text("Open DataType Archive File")

        manager = self.plugin.get_data_type_manager_handler()
        selected_file = file_chooser.askopenfilename()

        if not selected_file:
            return

        last_opened_dir = os.path.dirname(selected_file)
        Preferences.setProperty(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY, last_opened_dir)

        try:
            archive = manager.open_archive(selected_file, False, True)
            node = get_node_for_archive(tree, archive)
            if node is not None:
                tree.set_selected_node(node)
        except Exception as e:
            DataTypeManagerHandler.handle_archive_file_exception(self.plugin, ResourceFile(selected_file), e)

    def get_node_for_archive(self, tree, archive):
        root_node = tree.get_model_root()
        all_children = [child for child in root_node.children]
        for node in all_children:
            if isinstance(node, ArchiveNode) and node.archive == archive:
                return node
        return None

    def get_archive_directory(self):
        last_opened_dir_path = Preferences.get_property(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY)
        if last_opened_dir_path is not None:
            return os.path.abspath(last_opened_dir_path)

        # Start browsing in the installed type info directory if the user hasn't ever
        # specified an archive directory.
        archive_dir_path = get_type_info_dir_path()
        if archive_dir_path is None:
            # start the browsing in the user's preferred project directory if they have not opened
            # any other archives yet and we can'nt find the typeinfo directory.
            return os.path.abspath(GenericRunInfo.get_projects_dir_path())

        return os.path.abspath(archive_dir_path)

    def get_type_info_dir_path(self):
        try:
            dir = Application.get_module_data_sub_directory("Base", "typeinfo").get_file(False)
            if dir is None:
                return None
            return os.path.abspath(dir.get_absolute_path())
        except Exception as e:
            messagebox.showerror(None, str(e))
            return None

class GhidraFileChooser(filedialog.asksaveasfile):
    def __init__(self, tree):
        self.tree = tree

    def set_file_filter(self, file_filters):
        for filter in file_filters:
            self.add_filter(filter)

    def set_current_directory(self, directory):
        self.initialdir = os.path.abspath(directory)

class ExtensionFileFilter(filedialog.asksaveasfile):
    def __init__(self, extensions, description=""):
        super().__init__()
        self.extensions = [ext for ext in extensions]
        self.description = description

    def filter(self, file_path):
        return any(file_path.lower().endswith(ext) for ext in self.extensions)

class GhidraDataTypesProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        self.tree = None

    def get_tree(self):
        if not self.tree:
            # Initialize the tree here.
            pass
        return self.tree

    def set_tree(self, tree):
        self.tree = tree

class GhidraDataTypesManagerHandler:
    @staticmethod
    def handle_archive_file_exception(plugin, file, exception):
        messagebox.showerror(None, f"Error opening archive {file.name}: {str(exception)}")

# Initialize the plugin.
plugin = None  # Replace with your actual plugin instance.

action = OpenArchiveAction(plugin)
```

Please note that this is a direct translation of Java code into Python. The original code might not work as-is in Python, and some modifications may be necessary to make it run correctly.