import os
from collections import defaultdict

class VersionControlVersionSummary:
    def __init__(self):
        pass

    def run(self):
        if not current_program:
            print("This script should be run from a tool with no open programs")
            return

        root_folder = ask_project_folder("Choose root folder to recursively get version summaries")

        start_ts = os.times()[0]
        monitor.initialize(0)
        monitor.set_indeterminate(True)

        files_processed = 0
        version_counts = defaultdict(int)
        for file in ProjectDataUtils.descendant_files(root_folder):
            if monitor.is_cancelled():
                break

            files_processed += 1

            ver = 0
            if file.is_versioned():
                ver = file.get_latest_version()
            else:
                continue

            count = version_counts[ver]
            version_counts[ver] = count + 1

        end_ts = os.times()[0]

        print("Finished gathering summary info for folder: " + str(root_folder))
        print("Total files: " + str(files_processed))
        print("Total time: " + str(end_ts - start_ts))

        keys = sorted(list(version_counts.keys()))
        for ver in keys:
            count = version_counts[ver]
            print("Files with [" + str(ver) + "] versions: " + str(count))


# Usage
script = VersionControlVersionSummary()
script.run()
