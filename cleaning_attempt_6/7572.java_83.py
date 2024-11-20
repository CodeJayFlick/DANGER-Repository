import os
from collections import defaultdict

class FindErrors:
    def run(self):
        folder = input("Please select a project folder: ")
        
        programs = []
        self.find_programs(programs, folder)
        results = {}
        for program in programs:
            try:
                errors = len(os.listdir(f"{program}/bookmarks/ERROR"))
                results[program] = errors
            except Exception as e:
                print(f"problem looking at {program}: {e}")
        
        sorted_results = dict(sorted(results.items(), key=lambda item: item[1]))
        for program, error_count in sorted_results.items():
            print(f"{program}: {error_count}")

    def find_programs(self, programs, folder):
        files = os.listdir(folder)
        for file in files:
            if monitor.is_cancelled():  # This line is not defined
                return
            if file.endswith(".ghidra"):  # Assuming this is the extension of program files
                programs.append(file)
        
        folders = [f for f in os.listdir(folder) if os.path.isdir(os.path.join(folder, f))]
        for folder in folders:
            self.find_programs(programs, os.path.join(folder))

# Initialize monitor and start running script
monitor = None  # This line is not defined
script = FindErrors()
script.run()

