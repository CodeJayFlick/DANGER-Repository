class CopyTask:
    def __init__(self, dest_folder, src_folder=None, src_file=None):
        self.dest_folder = dest_folder
        if src_folder:
            self.src_folder = src_folder
        elif src_file:
            self.src_file = src_file

    def run(self):
        if self.src_folder:
            self.copy_folder()
        else:
            self.copy_file()

    def copy_folder(self):
        try:
            # If folder is a root folder, copy the contents thereof
            if not self.src_folder.parent:
                folders = [folder for folder in self.src_folder.get_folders()]
                for folder in folders:
                    folder.copy_to(self.dest_folder)
                files = [file for file in self.src_folder.get_files()]
                for file in files:
                    file.copy_to(self.dest_folder)
            else:
                self.src_folder.copy_to(self.dest_folder)
        except Exception as e:
            if isinstance(e, CancelledException):
                pass
            elif isinstance(e, IOError):
                msg = str(e) or str(e.__dict__)
                print(f"Folder Copy Failed: Could not copy folder {self.src_folder.name}. {msg}")

    def copy_file(self):
        try:
            self.src_file.copy_to(self.dest_folder)
        except Exception as e:
            if isinstance(e, CancelledException):
                pass
            elif isinstance(e, IOError):
                msg = str(e) or str(e.__dict__)
                print(f"File Copy Failed: Could not copy file {self.src_file.name}. {msg}")
