import tkinter as tk
from tkinter import filedialog, messagebox
from typing import List

class ChangedFilesDialog:
    def __init__(self, tool: str, files_list: List[str]):
        self.tool = tool
        self.files_list = files_list
        self.save_selected = False

    def build_main_panel(self):
        outer_panel = tk.Frame()
        file_panel = DomainFilesPanel(files_list)
        outer_panel.pack(side=tk.TOP)

        return outer_panel

    def save(self, files: List[str]):
        self.save_selected = True
        if len(files) > 0:
            SaveTask(tool=self.tool, files=files).start()
        else:
            close()

    def cancel_callback(self):
        close()

class DomainFilesPanel(tk.Frame):
    def __init__(self, files_list: List[str], title: str):
        super().__init__()
        self.files_list = files_list
        self.title = title

    def get_selected_domain_files(self) -> List[str]:
        return [file for file in self.files_list if file.get()]


class SaveTask:
    def __init__(self, tool: str, files: List[str]):
        super().__init__()
        self.tool = tool
        self.files = files

    def run(self):
        for file in self.files:
            # TO DO: implement the logic to save each file
            pass


class PluginTool:
    def __init__(self, tool_frame):
        self.tool_frame = tool_frame

    def show_dialog(self, dialog):
        # TO DO: implement the logic to display the dialog
        pass

    def execute(self, task):
        # TO DO: implement the logic to execute a task
        pass


class CancelTask:
    def __init__(self, monitor):
        self.monitor = monitor

    def run(self):
        if self.monitor.is_cancelled():
            return False
