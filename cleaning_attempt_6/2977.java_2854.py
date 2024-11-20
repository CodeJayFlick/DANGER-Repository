import os
from datetime import datetime

class BatchSegregate64bit:
    def __init__(self):
        pass

    def run(self):
        if not current_program:
            print("This script should be run from a tool with no open programs")
            return

        root_folder_32 = ask_project_folder("Choose root folder to recursively 'segregate'")
        proj_root = root_folder_32.get_project_data().get_root_folder()
        root_folder_32_str = os.path.join(root_folder_32.get_pathname(), "")
        root_folder_64_str = os.path.join(root_folder_32.get_pathname(), "-x64/")

        start_ts = datetime.now().timestamp()
        monitor.initialize(0)
        monitor.set_indeterminate(True)

        files_processed = 0
        for file in ProjectDataUtils.descendant_files(root_folder_32):
            if monitor.is_cancelled():
                break

            metadata = file.get_metadata()
            lang_id = metadata["Language ID"]
            if lang_id and ":64:" in lang_id:
                orig_name = file.get_pathname()
                dest_folder = resolve_path(proj_root, os.path.join(file.get_parent().get_pathname().replace(root_folder_32_str, ""), root_folder_64_str), True)
                new_file = file.move_to(dest_folder)
                print(f"Moved {orig_name} to {new_file.get_pathname()}")
                files_processed += 1
        end_ts = datetime.now().timestamp()

        print(f"Finished segregating for folder: {root_folder_32.get_pathname()}")
        print(f"Total files: {files_processed}")
        print(f"Total time: {(end_ts - start_ts)}")

    def resolve_path(self, folder, path, create_if_missing):
        if not path:
            return None

        parts = path.split("/")
        for part in parts:
            subfolder = folder.get_folder(part)
            if subfolder is None and create_if_missing:
                try:
                    subfolder = folder.create_folder(part)
                except Exception as e:
                    print(f"Error creating folder: {str(e)}")
                    return None
            if subfolder is None:
                return None

        return folder


# Usage example
script = BatchSegregate64bit()
script.run()

