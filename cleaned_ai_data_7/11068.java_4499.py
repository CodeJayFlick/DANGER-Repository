class VersionControlTask:
    def __init__(self, title: str, tool, list_of_domain_files, parent=None):
        self.list = list_of_domain_files
        self.action_id = None
        self.keep_checked_out = False
        self.create_keep = False
        self.comments = ""
        self.files_in_use = False
        self.tool = tool
        self.was_canceled = False
        self.parent = parent

    def show_dialog(self, add_to_version_control: bool, filename: str):
        import threading

        def runnable():
            from ghidra_framework_main_datatree.VersionControlDialog import VersionControlDialog
            vc_dialog = VersionControlDialog(add_to_version_control)
            vc_dialog.set_current_filename(filename)
            vc_dialog.set_multi_files(len(self.list) > 1)
            if not self.files_in_use:
                vc_dialog.set_keep_checkbox_enabled(True)
            else:
                vc_dialog.set_keep_checkbox_enabled(False)

            action_id = vc_dialog.show_dialog(self.tool, self.parent)
            keep_checked_out = vc_dialog.keep_checked_out()
            create_keep = vc_dialog.should_create_keep_file()
            comments = vc_dialog.get_comments()

            if len(comments) == 0:
                comments = None

        threading.run_swing_now(runnable)

    def check_files_in_use(self):
        self.files_in_use = False
        for domain_file in self.list:
            if domain_file.get_consumers().size() > 0:
                self.files_in_use = True
                return

    def check_files_for_unsaved_changes(self):
        for domain_file in self.list:
            if domain_file.modified_since_checkout():
                return True
        return False


class DomainFile:
    pass


class PluginTool:
    pass


def run_swing_now(runnable):
    # This function is not available in Python. It seems to be a Java-specific method.
    pass

# Usage example:

tool = PluginTool()
list_of_domain_files = [DomainFile(), ]
parent = None
task = VersionControlTask("Title", tool, list_of_domain_files, parent)
filename = "file_name"
add_to_version_control = True
task.show_dialog(add_to_version_control, filename)

