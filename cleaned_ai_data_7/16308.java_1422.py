import os
from urllib.request import urlretrieve
from pathlib import Path

class FileUtils:
    @staticmethod
    def download(source: str, destination_path: Path, file_name: str) -> None:
        try:
            urlretrieve(source, os.path.join(destination_path, file_name))
        except Exception as e:
            raise ValueError(f"Failed to download {source}: {str(e)}")

# Example usage:
file_utils = FileUtils()
destination_dir = Path("/path/to/your/directory")
file_utils.download("http://example.com/file.txt", destination_dir, "file.txt")
