import os

class BatchRename:
    def __init__(self):
        pass

    def run(self):
        if not current_program:  # Assuming 'current_program' is a global variable or function that checks for open programs.
            print("This script should be run from a tool with no open programs")
            return

        root_folder = input("Choose root folder: ")
        find_string = input("Enter foldername to find: ")
        replace_string = input("Enter replacement foldername: ")

        start_time = int(round(time.time()))
        monitor.initialize(0)
        monitor.setIndeterminate(True)

        folders_processed = 0
        folders_renamed = 0

        for root, dirs, files in os.walk(root_folder):
            if monitor.isCancelled():
                break

            for folder_name in dirs:
                if folder_name == find_string:
                    print(f"Found {root}/{folder_name}, renaming...")
                    os.rename(os.path.join(root, folder_name), os.path.join(root, replace_string))
                    folders_renamed += 1
                folders_processed += 1

        end_time = int(round(time.time()))
        print("Finished batch rename under folder: " + root_folder)
        print(f"Total folders: {folders_processed}")
        print(f"Total folders renamed: {folders_renamed}")
        print(f"Total time: {(end_time - start_time)}")

if __name__ == "__main__":
    script = BatchRename()
    script.run()

