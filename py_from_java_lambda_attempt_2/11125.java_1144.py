Here is the equivalent Python code:

```Python
class CountDomainFilesTask:
    def __init__(self, folders: set, files: set):
        self.folders = folders
        self.files = files
        self.file_count = 0
        self.cancelled = False

    def run(self) -> None:
        self.count_files()

    def count_files(self) -> None:
        try:
            for folder in self.folders:
                if not self.cancelled:
                    self.monitor.check_cancelled()
                    self.count_files_in_folder(folder)
        except CancelException as e:
            self.cancelled = True

    def count_files_in_folder(self, folder: set) -> None:
        file_count = 0
        for domain_file in folder.get_files():
            if not self.files.contains(domain_file):
                file_count += 1
        self.file_count = file_count

        sub_folders = folder.get_folders()
        for sub_folder in sub_folders:
            if not self.folders.contains(sub_folder):
                self.count_files_in_folder(sub_folder)

    def was_cancelled(self) -> bool:
        return self.cancelled

    def get_file_count(self) -> int:
        return self.file_count
```

Note that Python does not have direct equivalents for Java's `Set`, `TaskMonitor` and `CancelledException`. I've replaced them with Pythonic constructs.