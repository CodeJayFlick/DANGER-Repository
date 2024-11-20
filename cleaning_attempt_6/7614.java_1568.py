import os
from tkinter import filedialog, messagebox
from typing import List, Any

class FidPlugin:
    def __init__(self):
        self.fid_file_manager = None
        self.service = None
        self.create_action = None
        self.attach_action = None
        self.detach_action = None
        self.populate_action = None

    @property
    def fid_file_manager(self) -> Any:
        return self._fid_file_manager

    @fid_file_manager.setter
    def fid_file_manager(self, value: Any):
        self._fid_file_manager = value

    @property
    def service(self) -> Any:
        return self._service

    @service.setter
    def service(self, value: Any):
        self._service = value

    @property
    def create_action(self) -> Any:
        return self._create_action

    @create_action.setter
    def create_action(self, value: Any):
        self._create_action = value

    @property
    def attach_action(self) -> Any:
        return self._attach_action

    @attach_action.setter
    def attach_action(self, value: Any):
        self._attach_action = value

    @property
    def detach_action(self) -> Any:
        return self._detach_action

    @detach_action.setter
    def detach_action(self, value: Any):
        self._detach_action = value

    @property
    def populate_action(self) -> Any:
        return self._populate_action

    @populate_action.setter
    def populate_action(self, value: Any):
        self._populate_action = value

    def create_standard_actions(self):
        action = None

        # Create "Choose Active FidDbs" Action
        action = filedialog.askopenfilename(title="Select which FidDbs are used during Fid Search")
        if action:
            choose_active_fid_dbs(action)

        # Create "Create new empty FidDb" Action
        action = self.create_new_fid_db()
        if action:
            create_action.set_file_path(action)

        # Create "Attach existing FidDb" Action
        action = filedialog.askopenfilename(title="Attach an existing FidDb file from your file system")
        if action:
            attach_fid_db(action)

        # Create "Detach attached FidDb" Action
        action = self.detach_fid_file()
        if action:
            detach_action.set_file_path(action)

        # Create "Populate FidDb from programs" Action
        populate_fid_dialog = PopulateFidDialog(self, self.service)
        tool.show_dialog(populate_fid_dialog)

    def choose_active_fid_dbs(self):
        active_fid_configure_dialog = ActiveFidConfigureDialog(self.fid_file_manager.get_fids())
        tool.show_dialog(active_fid_configure_dialog)

    def create_new_fid_db(self) -> str:
        db_file_path = filedialog.asksaveasfilename(title="Create new FidDb file", defaultextension=".fidb")
        if not db_file_path.endswith(".fidb"):
            db_file_path += ".fidb"
        try:
            self.fid_file_manager.create_new_fid_database(db_file_path)
        except DuplicateFileException as e:
            messagebox.showerror("Error creating new FidDb file", "File already exists: " + db_file_path)
        except IOException as e:
            messagebox.showerror("Error creating new FidDb file", "Caught IOException creating FidDb file")
        return db_file_path

    def attach_fid_db(self, fid_db_path):
        self.fid_file_manager.add_user_fids(fid_db_path)

    def detach_fid_file(self) -> str:
        fid_file = ask_choice("Choose FidDb to detach", "Please choose the FidDb to detach",
                              self.fid_file_manager.get_user_added_files(), None)
        if fid_file is not None:
            self.fid_file_manager.remove_user_fid(fid_file)

    def enable_actions(self):
        at_least_one_fid_db = len(self.fid_file_manager.get_fids()) > 0
        at_least_one_user_fid_db = len(self.fid_file_manager.get_user_added_files()) > 0

        if at_least_one_fid_db:
            self.create_action.set_enabled(True)
            self.attach_action.set_enabled(True)

        if at_least_one_user_fid_db:
            self.detach_action.set_enabled(True)
            self.populate_action.set_enabled(True)


class PopulateFidDialog:

    def __init__(self, tool):
        pass

    # Method to populate an existing FidDb with all programs under a domain folder
    def show(self):
        if self.is_canceled():
            return None

        s = self.get_choice_value()
        return s


def ask_file(title: str, approve_button_text: str) -> Any:
    chooser = filedialog.asksaveasfilename(title=title)
    return chooser


def ask_choice(title: str, message: str, choices: List[Any], default_value: Any) -> Any:
    dialog = AskDialog(None, title, message, "STRING", choices, default_value)
    if dialog.is_canceled():
        return None

    s = dialog.get_choice_value()
    return s


class ActiveFidConfigureDialog:

    def __init__(self):
        pass
