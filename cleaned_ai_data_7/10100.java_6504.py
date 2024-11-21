import os

class FileSystemInitializer:
    def run(self):
        for file in os.listdir('/tmp'):
            if file.startswith('ghidra_') and file.endswith('.db'):
                try:
                    os.remove(os.path.join('/tmp', file))
                except Exception as e:
                    print(f"Error removing {file}: {str(e)}")

    @property
    def name(self):
        return "FileSystem Module"

# Usage example
initializer = FileSystemInitializer()
initializer.run()

print(initializer.name)
