class CopyFileVersionTask:
    def __init__(self, file: str, version: int, dest_folder: str):
        self.file = file
        self.version = version
        self.dest_folder = dest_folder

    def run(self) -> None:
        try:
            print(f"Copying {self.file} version {self.version}...")
            if not copy_file_version_to(self.file, self.version, self.dest_folder):
                raise Exception("Version Copy Failed")
        except CancelledException as e:
            pass
        except IOException as e:
            handle_exception(e)

def copy_file_version_to(file: str, version: int, dest_folder: str) -> bool:
    # Implement your logic here to copy the file version
    return True

def handle_exception(exception: Exception):
    # Handle exception in a way that makes sense for your application
    pass
