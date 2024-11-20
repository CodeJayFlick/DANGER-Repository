Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import messagebox
from collections import set

class ProjectDataDeleteAction:
    def __init__(self):
        self.icon = None  # equivalent to ResourceManager.loadImage("images/page_delete.png")

    def get_icon(self):
        return self.icon

    def confirm_delete(self, file_count, files, parent):
        if file_count == 0:
            message = "Are you sure you want to delete the selected empty folder(s)?"
        elif file_count == 1:
            if not files:
                file_name = None
            else:
                file_name = next(iter(files)).name
            return f"Are you sure you want to permanently delete \"{file_name}\"?"
        else: 
            message = f"Are you sure you want to permanently delete the {file_count} selected files?"

        option_dialog_builder = tk.messagebox.askyesno("Confirm Delete", message)
        return option_dialog_builder

    def create_delete_task(self, context, files, folders):
        # Task 2 - perform the delete--this could take a while
        if not files and not folders:
            file_count = 0
        elif len(files) == 1:
            file_count = 1
        else: 
            file_count = len(files)

        return {"folders": folders, "files": files, "file_count": file_count}

    def action_performed(self):
        context = None  # equivalent to ProjectDataContext

        if not self.is_enabled_for_context(context):
            return False

        count_task = self.count_domain_files(context)
        new_task_launcher(count_task)

        if count_task.was_cancelled():
            return True

        file_count = count_task.get_file_count()
        files = set()  # equivalent to CollectionUtils.asSet
        folders = set()

        if not self.confirm_delete(file_count, files, context):
            return False

        delete_task = self.create_delete_task(context, files, folders)
        new_task_launcher(delete_task)

    def is_enabled_for_context(self, context):
        if not (context.has_one_or_more_files_and_folders()):
            return False
        if context.is_read_only_project():
            return False
        return not context.contains_root_folder()

    def count_domain_files(self, context):
        # Task 1 - count the files. This probably does not need a task, but just in case.
        folders = set()  # equivalent to CollectionUtils.asSet
        files = set()
        
        if len(folders) == 0 and len(files) > 0:
            file_count = len(files)
        elif len(folders) > 1 or (len(folders) == 1 and not files):
            return {"file_count": None, "was_cancelled": False}
        else: 
            return {"file_count": 1, "was_cancelled": True}

    def get_message(self, file_count, selected_files):
        if file_count == 0:
            message = "Are you sure you want to delete the selected empty folder(s)?"
        elif file_count == 1:
            if not selected_files:
                return f"Are you sure you want to permanently delete the selected files?"
            else: 
                return f"Are you sure you want to permanently delete \"{next(iter(selected_files)).name}\"?"

        # multiple files selected
        return f"Are you sure you want to permanently delete the {file_count} selected files?"