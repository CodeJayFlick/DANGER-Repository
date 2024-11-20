import os
from datetime import datetime

class VersionControlAddAll:
    def __init__(self):
        pass

    def run(self):
        if not hasattr(globals(), 'current_program'):
            print("This script should be run from a tool with no open programs")
            return

        root_folder = input("Choose the root folder to recursively add files to version control: ")
        check_in_comment = input("Enter the comment that will be used (default is 'Initial import'): ") or "Initial import"

        start_time = datetime.now()
        print(f"Starting at {start_time}")

        file_count = 0
        for root, dirs, files in os.walk(root_folder):
            for file in files:
                if not file.endswith('.ghidra'):
                    try:
                        # Add the file to version control here (this is where you would put your code)
                        print(f"Adding {file}...")
                        file_count += 1
                    except Exception as e:
                        print(f"Error adding {file}: {str(e)}")

        end_time = datetime.now()
        print(f"Finished at {end_time}")
        print(f"Total files: {file_count}")

if __name__ == "__main__":
    VersionControlAddAll().run()
