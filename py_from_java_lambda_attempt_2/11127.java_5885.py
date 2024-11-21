Here is the translation of the Java code into Python:

```Python
class FileCountStatistics:
    def __init__(self, file_count):
        self.file_count = file_count
        self.read_only_skipped = 0
        self.general_failure = 0
        self.file_in_use = 0
        self.versioned_declined = 0
        self.checked_out_versioned = 0
        self.deleted = 0

    def increment_deleted(self):
        self.deleted += 1

    def get_total_deleted(self):
        return self.deleted

    def get_file_count(self):
        return self.file_count

    def increment_file_count(self, size):
        self.file_count += size

    def increment_read_only_skipped(self):
        self.read_only_skipped += 1

    def increment_general_failure(self):
        self.general_failure += 1

    def increment_file_in_use(self):
        self.file_in_use += 1

    def increment_versioned_declined(self):
        self.versioned_declined += 1

    def increment_checked_out_versioned(self):
        self.checked_out_versioned += 1

    def show_report(self, parent):
        if self.get_total_processed() == 1:
            return
        if self.deleted == self.file_count:
            return

        message = self.build_report_message()
        OptionDialogBuilder(builder="Delete Files Summary", message=message)
        builder.set_message_type(OptionDialog.INFORMATION_MESSAGE)
        builder.show(parent)

    def build_report_message(self):
        message = f"{self.deleted} file(s) deleted!"
        if self.get_total_not_deleted() > 0:
            message += "<br><br>Files not deleted:<br>"
            table = ""
            if self.file_in_use > 0:
                table += f"In Use: {self.file_in_use}<br>"
            if self.versioned_declined > 0:
                table += f"Versioned: {self.versioned_declined}<br>"
            if self.checked_out_versioned > 0:
                table += f"Checked-out: {self.checked_out_versioned}<br>"
            if self.read_only_skipped > 0:
                table += f"Read only: {self.read_only_skipped}<br>"
            if self.general_failure > 0:
                table += f"Other: {self.general_failure}<br>"
            message += table
        return message

    def get_total_processed(self):
        return self.read_only_skipped + self.general_failure + self.file_in_use + \
               self.versioned_declined + self.checked_out_versioned + self.deleted

    def get_total_not_deleted(self):
        return self.get_total_processed() - self.deleted


# Example usage:
stats = FileCountStatistics(10)
stats.increment_file_count(5)
stats.show_report("Parent")
```

Please note that Python does not have direct equivalent of Java's OptionDialog and docking. It is a GUI toolkit for creating graphical user interfaces (GUIs) in the Tkinter library, which is included with most standard Python distributions.