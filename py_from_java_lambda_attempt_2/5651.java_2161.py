Here is the translation of the Java code into Python:

```Python
class AbstractFileExtractorTask:
    def __init__(self, title: str, can_cancel: bool, has_progress: bool, is_modal: bool, root_output_dir: str):
        self.title = title
        self.can_cancel = can_cancel
        self.has_progress = has_progress
        self.is_modal = is_modal
        self.root_output_directory = root_output_dir

    def start_extract(self, fs: 'GFileSystem', src_dir: 'GFile' or None, monitor: 'TaskMonitor'):
        if not src_dir:
            src_dir = fs.lookup(None)
        self.process_directory(src_dir, self.root_output_directory, monitor)

    def process_directory(self, src_gfile_directory: 'GFile', dest_directory: str, monitor: 'TaskMonitor') -> None or CancelledException:
        if is_special_directory(src_gfile_directory):
            return

        for file in fs.get_listing(src_gfile_directory):
            monitor.check_cancelled()

            dest_fname = self.map_source_filename_to_dest(file)
            dest_fs_file = os.path.join(dest_directory, dest_fname)

            if file.is_directory():
                self.process_directory(file, dest_fs_file, monitor)
            else:
                self.process_file(file, dest_fs_file, monitor)

    def process_file(self, src_file: 'GFile', dest_fs_file: str, monitor: 'TaskMonitor') -> None or CancelledException:
        try:
            if not os.path.isabs(dest_fs_file):
                raise ValueError("Extracted file {} would be outside of root destination directory {}".format(src_file.get_path(), self.root_output_directory))

            with open(dest_fs_file, "wb") as f:
                in_stream = self.get_source_file_input_stream(src_file, monitor)
                if in_stream is not None:
                    bytes_copied = 0
                    while True:
                        chunk = in_stream.read(1024 * 1024)  # Read a megabyte at a time.
                        if len(chunk) == 0:  # If the file has been fully read, break out of loop.
                            break

                        f.write(chunk)
                        bytes_copied += len(chunk)

                    self.total_bytes_exported_count += bytes_copied
                    self.total_files_exported_count += 1
        except CancelledException:
            raise
        except Exception as e:
            if not self.handle_unexpected_exception(src_file, e):
                raise

    def map_source_filename_to_dest(self, src_file: 'GFile') -> str:
        return FSUtilities.get_safe_filename(src_file.name)

    def handle_unexpected_exception(self, file: 'GFile', exception: Exception) -> bool:
        return False

    @property
    def total_files_exported_count(self):
        return self._total_files_exported_count

    @total_files_exported_count.setter
    def total_files_exported_count(self, value):
        self._total_files_exported_count = value

    @property
    def total_dirs_exported_count(self):
        return self._total_dirs_exported_count

    @total_dirs_exported_count.setter
    def total_dirs_exported_count(self, value):
        self._total_dirs_exported_count = value

    @property
    def total_bytes_exported_count(self):
        return self._total_bytes_exported_count

    @total_bytes_exported_count.setter
    def total_bytes_exported_count(self, value):
        self._total_bytes_exported_count = value

def is_special_directory(directory: 'GFile') -> bool:
    if not directory:
        return False

    switch directory.name:
        case "\0\0\0\0HFS+ Private Data":
            case ".HFS+ Private Directory Data\r":
                return True
    return False

def get_source_file_input_stream(self, file: 'GFile', monitor: 'TaskMonitor') -> InputStream or CancelledException:
    return fs.get_input_stream(file, monitor)
```

Note that Python does not have a direct equivalent to Java's `throws` keyword. Instead, you can use the built-in exception handling mechanism in Python.