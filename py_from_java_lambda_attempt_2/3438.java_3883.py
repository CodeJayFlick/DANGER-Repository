Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog
from tkinter.messagebox import showerror, showinfo

class RestoreDialog:
    def __init__(self):
        self.plugin = None
        self.action_complete = False
        self.archive_label = None
        self.archive_field = None
        self.archive_browse = None
        self.restore_label = None
        self.restore_field = None
        self.restore_browse = None
        self.project_name_label = None
        self.project_name_field = None

    def build_main_panel(self):
        outer_panel = tk.Frame()
        gbl = tk.GridBagLayout()
        outer_panel.configure(layout=gbl)

        archive_label = tk.Label(outer_panel, text="Archive File")
        gbl.attach_widget(archive_label, (0, 0), expandx=True)
        self.archive_label = archive_label

        archive_field = tk.Entry(outer_panel, width=40)
        gbl.attach_widget(archive_field, (1, 0))
        self.archive_field = archive_field

        archive_browse = tk.Button(outer_panel, text="...")
        archive_browse.bind("<Button-1>", lambda event: self.choose_archive_file())
        gbl.attach_widget(archive_browse, (2, 0), expandx=True)
        self.archive_browse = archive_browse

        restore_label = tk.Label(outer_panel, text="Restore Directory")
        gbl.attach_widget(restore_label, (3, 0))
        self.restore_label = restore_label

        restore_field = tk.Entry(outer_panel, width=40)
        gbl.attach_widget(restore_field, (4, 0))
        self.restore_field = restore_field

        restore_browse = tk.Button(outer_panel, text="...")
        restore_browse.bind("<Button-1>", lambda event: self.choose_restore_directory())
        gbl.attach_widget(restore_browse, (5, 0), expandx=True)
        self.restore_browse = restore_browse

        project_name_label = tk.Label(outer_panel, text="Project Name")
        gbl.attach_widget(project_name_label, (6, 0))
        self.project_name_label = project_name_label

        project_name_field = tk.Entry(outer_panel, width=40)
        gbl.attach_widget(project_name_field, (7, 0))
        self.project_name_field = project_name_field

        return outer_panel

    def ok_callback(self):
        if self.check_input():
            self.action_complete = True
            self.close()
        else:
            showerror("Error", "Invalid input")

    def cancel_callback(self):
        self.status_text("")
        self.close()

    def showDialog(self, path_name, project_locator):
        self.archive_path_name = path_name
        self.restore_url = project_locator

        if not self.project_name_field.get():
            self.project_name_field.insert(0, ArchivePlugin.getProjectName(path_name))

        archive_file = tk.filedialog.askopenfilename()
        restore_dir = tk.filedialog.askdirectory()

        self.archive_field.delete(0, tk.END)
        self.archive_field.insert(0, path_name)

        if project_locator:
            self.restore_field.delete(0, tk.END)
            self.restore_field.insert(0, project_locator.getLocation())

        return self.action_complete

    def get_archive_path_name(self):
        archive = self.archive_field.get().strip()
        if not archive:
            return None
        file = tk.filedialog.askopenfilename(initialdir=archive)

        if file and file.endswith(ArchivePlugin.ARCHIVE_EXTENSION):
            return file
        else:
            return None

    def get_restore_url(self):
        return self.restore_url

    def check_input(self):
        archive_name = self.get_archive_path_name()
        if not archive_name or not archive_name.strip():
            showerror("Error", "Specify a valid archive file")
            return False

        restore_dir = self.restore_field.get().strip()

        if not restore_dir:
            showerror("Error", "Specify a valid project directory")
            return False

        restore_project_name = self.project_name_field.get().strip()
        if not restore_project_name or not NamingUtilities.isValidName(restore_project_name):
            showerror("Error", "Specify a valid project name")
            return False
        else:
            file = tk.filedialog.askopenfilename(initialdir=GenericRunInfo.getProjectsDirPath())
            self.restore_url = ProjectLocator(file, restore_project_name)
            return True

    def choose_archive_file(self):
        if not self.jar_filechooser:
            self.jar_filechooser = tk.filedialog.asksaveasfile()
            self.jar_filechooser.title("Restore a Ghidra Project - Archive")
            last_dir_selected = Preferences.getProperty(ArchivePlugin.LAST_ARCHIVE_DIR)
            if last_dir_selected and os.path.exists(last_dir_selected):
                file = tk.FileDialog.askdirectory(initialdir=last_dir_selected)

        selected_file = self.jar_filechooser.getselectedfile()
        if selected_file:
            return selected_file

    def choose_restore_directory(self):
        if not self.dir_chooser:
            self.dir_chooser = tk.filedialog.asksaveasfile()

        file = self.dir_chooser.askdirectory(initialdir=GenericRunInfo.getProjectsDirPath())
        if file and os.path.exists(file):
            return file
```

Please note that this is a translation of the Java code into Python, not an actual implementation in Python. The original code seems to be part of a larger program or framework (Ghidra), which may require additional setup or dependencies for proper functioning.