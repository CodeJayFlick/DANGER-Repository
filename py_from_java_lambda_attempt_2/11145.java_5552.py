Here is the translation of the given Java code into Python:

```Python
import os
from tkinter import messagebox as msgbox
from tkinter.filedialog import asksaveasfilename

class VersionControlAddAction:
    def __init__(self):
        self.plugin = None  # Initialize plugin variable

    def set_plugin(self, plugin):
        self.plugin = plugin

    def is_enabled_for_context(self, context):
        if not os.path.exists('path_to_your_file'):  # Replace with your file path
            return False
        selected_files = [file for file in context.get_selected_files()]
        for domain_file in selected_files:
            if domain_file.can_add_to_repository():
                return True
        return False

    def action_performed(self, context):
        self.add_to_version_control(context.get_selected_files())

    def add_to_version_control(self, files):
        unversioned = [file for file in files if file.is_version_control_supported() and not file.is_versioned()]
        if len(unversioned) == 0:
            return
        list_of_domain_files = []
        changed_list = []
        for domain_file in unversioned:
            if domain_file.is_busy():
                msgbox.showwarning("Add To Version Control Failed", "One or more selected files is currently being modified!")
                return
            if not self.can_close_domain_file(domain_file):
                self.plugin.set_status_info("Add to version control canceled")
                return
            list_of_domain_files.append(domain_file)
            if domain_file.is_changed():
                changed_list.append(domain_file)

        if len(changed_list) > 0:
            dialog = ChangedFilesDialog(self.plugin, changed_list)
            dialog.set_cancel_tooltip_text("Cancel Add to Version Control")
            if not dialog.show_dialog():  # blocks until the user hits Save or Cancel
                self.plugin.set_status_info("Add to version control canceled")
                return
            for i in range(len(changed_list)):
                df = changed_list[i]
                if df.is_changed():
                    list_of_domain_files.remove(df)

        if len(list_of_domain_files) > 0:
            task = AddToVersionControlTask(list_of_domain_files, self.plugin)
            self.plugin.execute(task)


class AddToVersionControlTask:
    def __init__(self, files, tool):
        super().__init__()
        self.files = files
        self.tool = tool

    def run(self):
        for file in self.files:
            name = file.name
            print(f"Adding {name} to Version Control")
            if action_id != "APPLY_TO_ALL":
                show_dialog(True, name)
            if action_id == "CANCEL":
                return
            # Note: this used to be a sleep(200) 
            Swing.allowSwingToProcessEvents()
            file.add_to_version_control(comments, keep_checked_out)


class ChangedFilesDialog:
    def __init__(self, tool, files):
        self.tool = tool
        self.files = files

    def set_cancel_tooltip_text(self, text):
        pass  # Replace with your code to set the cancel tooltip text

    def show_dialog(self):  # blocks until the user hits Save or Cancel
        return True


class DomainFile:
    def __init__(self, name):
        self.name = name
        self.is_busy = False
        self.is_changed = False

    def can_add_to_repository(self):
        pass  # Replace with your code to check if file can be added to repository

    def is_version_control_supported(self):
        return True  # Replace with your code to check if file supports version control

    def is_versioned(self):
        return False  # Replace with your code to check if file is already in the version control system

    def add_to_version_control(self, comments):  # Add this method
        pass  # Replace with your code to add a domain file to the version control system


class PluginTool:
    def __init__(self):
        self.tool = None  # Initialize tool variable

    def set_status_info(self, message):
        print(message)

    def execute(self, task):  # Execute this method
        pass  # Replace with your code to execute a task in the plugin tool


class VersionControlTask:
    def __init__(self, name, tool, files, frame):
        self.name = name
        self.tool = tool
        self.files = files
        self.frame = frame

    def run(self):  # Run this method
        pass  # Replace with your code to execute a task in the version control system


class VersionControlDialog:
    APPLY_TO_ALL = "APPLY_TO_ALL"
    CANCEL = "CANCEL"


# Usage example:

action = VersionControlAddAction()
plugin_tool = PluginTool()

files_to_add = [DomainFile("file1"), DomainFile("file2")]
action.set_plugin(plugin_tool)
action.add_to_version_control(files_to_add)

```

Please note that this is a Python translation of the given Java code. It may not work as expected without proper modifications and replacements with your actual file paths, method implementations, etc.

Also, please be aware that some parts of the original Java code are missing in this Python version (like Swing-related classes), so you might need to add or modify them according to your needs.