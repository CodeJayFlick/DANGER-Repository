import os
from urllib.parse import urlparse, urlunparse
from typing import List

class GClassLoader:
    def __init__(self, module_dirs: List[str]):
        self.urls = []
        for dir in module_dirs:
            bin_dir = os.path.join(dir, 'bin', 'main')
            if os.path.exists(bin_dir):
                self.add_file_url(os.path.abspath(bin_dir))
            lib_dir = os.path.join(dir, 'lib')
            if os.path.isdir(lib_dir):
                jar_files = [os.path.join(lib_dir, f) for f in os.listdir(lib_dir)]
                for file in jar_files:
                    if is_jar_file(file):
                        self.add_file_url(os.path.abspath(file))

    def add_file_url(self, path: str):
        try:
            url_path = urlparse(path)
            new_path = urlunparse((url_path.scheme, 'localhost', url_path.path, '', '', ''))  # Make it a local URL
            self.urls.append(new_path)
        except ValueError as e:
            raise AssertionError("Can't happen since we checked that it exists.") from e

    def is_jar_file(self, file: str):
        return os.path.exists(file) and file.endswith('.jar')

# Example usage:

if __name__ == "__main__":
    module_dirs = ['/path/to/module1', '/path/to/module2']
    loader = GClassLoader(module_dirs)
