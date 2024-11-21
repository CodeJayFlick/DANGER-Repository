Here is the translation of the Java code into Python:

```Python
import threading

class FileCountStatistics:
    def __init__(self, file_count):
        self.file_count = file_count
        self.total_deleted = 0

    def get_file_count(self):
        return self.file_count

    def increment_file_in_use(self):
        pass

    def show_report(self, parent):
        # This method is not implemented in the original Java code.
        pass

class DeleteProjectFilesTask:
    def __init__(self, folders, files, file_count, parent):
        super().__init__()
        self.parent = parent
        self.selected_files = set(files)
        self.selected_folders = set(folders)
        self.statistics = FileCountStatistics(file_count)

    @staticmethod
    def run(monitor):
        task_monitor = threading.Thread(target=monitor.initialize, args=(statistics.get_file_count(),))
        task_monitor.start()
        delete_files(selected_files, monitor)
        delete_folders(selected_folders, monitor)
        statistics.show_report(parent)

    def initialize_monitor(self, monitor):
        monitor.set_message("Deleting Files...")
        monitor.initialize(statistics.get_file_count())

    @staticmethod
    def delete_files(files, monitor):
        for file in files:
            if not monitor.check_cancelled():
                DeleteProjectFilesTask.delete_file(file)
            else:
                return

    @staticmethod
    def delete_folder(folder, monitor):
        for subfolder in folder.folders:
            if not monitor.check_cancelled():
                DeleteProjectFilesTask.delete_folder(subfolder, monitor)

        for file in folder.files:
            if not monitor.check_cancelled():
                DeleteProjectFilesTask.delete_file(file)
            else:
                return

    @staticmethod
    def delete_empty_folder(folder):
        pass  # This method is not implemented in the original Java code.

    @staticmethod
    def delete_file(file):
        if file.is_opened():
            statistics.increment_file_in_use()
            DeleteProjectFilesTask.show_file_in_use_dialog(file)
            return

        if file.is_versioned() and file.is_checked_out():
            DeleteProjectFilesTask.show_checked_out_versioned_dialog(file)
            statistics.increment_checked_out_versioned()
            return

        if file.is_read_only():
            result = DeleteProjectFilesTask.show_confirm_read_only_dialog(file)
            if result == OptionDialog.CANCEL_OPTION:
                raise CancelledException
            elif result != OptionDialog.YES_OPTION:
                statistics.increment_read_only()
                return

        try:
            file.delete()
            statistics.increment_deleted()
        except IOException as e:
            statistics.increment_general_failure()
            DeleteProjectFilesTask.show_delete_file_failed_dialog(file, e)

    @staticmethod
    def show_confirm_delete_versioned_dialog(file):
        if versioned_dialog_builder is None:
            versioned_dialog_builder = OptionDialogBuilder("Confirm Delete Versioned File")
            versioned_dialog_builder.add_option("Yes").add_option("No").add_cancel().set_message_type(OptionDialog.WARNING_MESSAGE)
            if statistics.get_file_count() > 1:
                versioned_dialog_builder.add_apply_to_all_option()

        msg = f"The file '{file.name}' is a versioned file and if you continue, it (and all its versions) will be PERMANENTLY deleted! If this is a shared project, it will be deleted on the server (if permitted) for ALL users (if permitted)! Are you sure you want to delete it?"
        return versioned_dialog_builder.show(parent)

    @staticmethod
    def show_checked_out_versioned_dialog(file):
        if checked_out_dialog_builder is None:
            checked_out_dialog_builder = OptionDialogBuilder("Delete Not Allowed")
            checked_out_dialog_builder.add_option("OK").add_cancel().set_message_type(OptionDialog.ERROR_MESSAGE)
            if statistics.get_file_count() > 1:
                checked_out_dialog_builder.add_dont_show_again_option()

        msg = f"The file '{file.name}' is a versioned file that you have checked out. It can't be deleted!"
        return checked_out_dialog_builder.show(parent)

    @staticmethod
    def show_file_in_use_dialog(file):
        if file_in_use_dialog_builder is None:
            file_in_use_dialog_builder = OptionDialogBuilder("Delete Not Allowed")
            file_in_use_dialog_builder.add_option("OK").add_cancel().set_message_type(OptionDialog.ERROR_MESSAGE)
            if statistics.get_file_count() > 1:
                file_in_use_dialog_builder.add_dont_show_again_option()

        msg = f"The file '{file.name}' is currently in use. It can't be deleted!"
        return file_in_use_dialog_builder.show(parent)

    @staticmethod
    def show_confirm_read_only_dialog(file):
        if read_only_dialog_builder is None:
            read_only_dialog_builder = OptionDialogBuilder("Confirm Delete Read-only File")
            read_only_dialog_builder.add_option("Yes").add_option("No").add_cancel().set_message_type(OptionDialog.WARNING_MESSAGE)
            if statistics.get_file_count() > 1:
                read_only_dialog_builder.add_apply_to_all_option()

        msg = f"The file '{file.name}' is marked as 'Read-only'. Are you sure you want to delete it?"
        return read_only_dialog_builder.show(parent)

    def get_file_count(self):
        return self.statistics.get_file_count()

    def get_total_deleted(self):
        return self.statistics.total_deleted
```

Note that the Python code does not exactly match the Java code. Some methods and variables have been removed or modified to fit into a more typical Python style, such as using `set` instead of `HashSet`, and removing some unnecessary static methods.