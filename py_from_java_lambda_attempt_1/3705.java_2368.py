Here is the translation of the given Java code into Python:

```Python
import logging
from tkinter import filedialog, messagebox

class ArchiveUtils:
    def __init__(self):
        pass  # utils class

    @staticmethod
    def save_as(component: object, archive) -> None:
        if not isinstance(archive, FileArchive):
            raise TypeError("Invalid type for 'archive'")

        try:
            file = filedialog.asksaveasfilename()
            if file is None or file == "":
                return  # User cancelled the operation

            if file == str(archive.file):  # Check if user chose same filename
                archive.save()
            else:
                archive.save_as(file)

        except DuplicateFileException as e:
            logging.error("Duplicate File Exception: %s", e)
        except IOException as e:
            logging.error("IOException: %s", e)

    @staticmethod
    def save(component: object, archive) -> None:
        if not isinstance(archive, Archive):
            raise TypeError("Invalid type for 'archive'")

        try:
            if not archive.is_savable():
                archive.save_as(component)
            else:
                archive.save()

        except DuplicateFileException as e:
            logging.error("Duplicate File Exception: %s", e)
        except IOException as e:
            logging.error("IOException: %s", e)

    @staticmethod
    def can_close(archive_list, component) -> bool:
        for archive in archive_list:
            if not ArchiveUtils.can_close(archive, component):
                return False

        return True

    @staticmethod
    def lock_archive(archive) -> None:
        try:
            archive.acquire_write_lock()
        except ReadOnlyException as e:
            logging.error("Unable to Lock File for Writing: %s", e)
        except LockException as e:
            logging.error("Unable to obtain lock for archive: %s\n%s", archive.name, e)
        except IOException as e:
            logging.error("Problem attempting to lock archive: %s\n%s", archive.name, e)

    @staticmethod
    def get_file(component, archive) -> File | None:
        file_chooser = ArchiveFileChooser(component)
        archive_name = str(archive.name)
        file = file_chooser.prompt_user_for_file(archive_name)

        if file is None or file == "":
            return None

        if file == str(archive.file):
            return file
        elif file.exists():
            if OptionDialog.show_yes_no_dialog_with_no_as_default_button(component, "Overwrite Existing File?", f"Do you want to overwrite existing file {file.abspath}?") != OptionDialog.OPTION_ONE:
                return None

            try:
                file.delete()
            except Exception as e:
                logging.error("Error deleting file: %s", e)
                return None
        elif archive.archive_manager.is_in_use(file):
            messagebox.showinfo(component, "Cannot Perform Save As", f"Cannot save archive to {file.name} because it is in use.")
            return None

        return file

    @staticmethod
    def delete_archive_file(file) -> bool:
        try:
            FileDataTypeManager.delete(file)
            return True
        except Exception as e:
            logging.error("Error deleting file: %s", e)

        return file.exists() and file.delete()

    @staticmethod
    def can_close(archive, component) -> bool | None:
        if not archive.is_changed():
            return True

        result = OptionDialog.show_yes_no_cancel_dialog(component, "Save Archive?", f"Datatype Archive '{str(archive.name)}' has been changed.\n Do you want to save the changes?")

        if result == OptionDialog.CANCEL_OPTION:
            return False
        elif result == OptionDialog.NO_OPTION:
            try:
                (FileArchive)(archive).release_write_lock()
            except IOException as e:
                logging.error("Unable to release File Archive write lock: %s", e)
                return False

            return True

        return ArchiveUtils.save_archive(archive, component)

    @staticmethod
    def save_archive(archive, component) -> bool | None:
        try:
            ArchiveUtils.save(component, archive)
            return True
        except DuplicateFileException as e:
            logging.error("Unable to Save Archive: %s", e)
        except IOException as e:
            logging.error("Unexpected exception attempting to save archive: %s", e)

        return False

class OptionDialog:
    @staticmethod
    def show_yes_no_dialog_with_no_as_default_button(component, title, message) -> int:
        pass  # implementation not provided in the given Java code

    @staticmethod
    def show_yes_no_cancel_dialog(component, title, message) -> int:
        pass  # implementation not provided in the given Java code

class ArchiveFileChooser:
    def __init__(self, component):
        self.component = component

    def prompt_user_for_file(self, archive_name) -> File | None:
        return filedialog.asksaveasfilename()  # implementation not provided in the given Java code
```

Please note that this translation is based on my understanding of your requirements and may need further modifications to work correctly with Python's syntax and libraries.