import tkinter as tk
from PIL import ImageTk, Image

class SaveVersionTrackingSessionAction:
    def __init__(self):
        self.controller = None
        self.icon = None

    def set_icon(self, icon_path):
        if not self.icon:
            self.icon = Image.open(icon_path)
            self.icon = ImageTk.PhotoImage(self.icon)

    def set_controller(self, controller):
        self.controller = controller

    def get_description(self):
        return "Save Version Tracking Changes"

    def is_enabled(self):
        return bool(self.has_unsaved_version_tracking_changes())

    def has_unsaved_version_tracking_changes(self):
        if not self.controller:
            return False
        session = self.controller.get_session()
        if not session:
            return False
        if isinstance(session, VTSessionDB):
            if session.is_changed():
                return True
        program = self.controller.get_destination_program()
        return program.is_changed()

    def is_add_to_popup(self):
        return True

class SaveTask:
    pass  # This class needs to be implemented in Python equivalent of the Java code.

def main():
    root = tk.Tk()
    action = SaveVersionTrackingSessionAction()
    # Set icon and controller
    action.set_icon("images/disk.png")
    action.set_controller(VTController())  # VTController should be defined elsewhere

    def on_actionPerformed(event):
        if not action.has_unsaved_version_tracking_changes():
            return
        session = action.controller.get_session()
        if isinstance(session, VTSessionDB):
            vt_domain_file = session.get_domain_file()
            save_task = SaveTask(vt_domain_file)
            TaskLauncher().launch(save_task)  # This class needs to be implemented in Python equivalent of the Java code.
            program = action.controller.get_destination_program()
            destination_program_file = program.get_domain_file()
            if destination_program_file.is_changed():
                save_task = SaveTask(destination_program_file)
                TaskLauncher().launch(save_task)  # This class needs to be implemented in Python equivalent of the Java code.

        action.controller.refresh()

    root.bind("<Button-1>", on_actionPerformed)

if __name__ == "__main__":
    main()
