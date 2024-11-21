import os
from ghidra import GhidraScript

class VersionControl_ResetAll(GhidraScript):
    def __init__(self):
        pass

    @staticmethod
    def run():
        if current_program:
            print("This script should be run from a tool with no open programs")
            return

        root_folder = ask_project_folder("Choose root folder to recursively 'reset to base rev'")

        if not confirm_delete(f"Are you sure you want to delete all revisions of files in {root_folder}?"):
            return

        start_time = os.times()
        monitor.initialize(0)
        monitor.set_indeterminate(True)

        files_processed = 0
        for file in ProjectDataUtils.descendant_files(root_folder):
            if monitor.is_cancelled():
                break

            if (file.get_content_type() != ProgramContentHandler.PROGRAM_CONTENT_TYPE or 
                    not file.is_versioned() or file.get_latest_version() < 2):
                continue

            monitor.set_message(f"Resetting {file.name} ({file.get_latest_version()}")
            try:
                for ver_num in range(file.get_latest_version(), 1, -1):
                    file.delete(ver_num)
                files_processed += 1
            except Exception as e:
                print(f"Failed to reset {file.path} version: {str(e)}")

        end_time = os.times()

        print(f"Finished resetting to base rev for folder: {root_folder}")
        print(f"Total files: {files_processed}")
        print(f"Total time: {(end_time[4] - start_time[4])}")

if __name__ == "__main__":
    VersionControl_ResetAll().run()
