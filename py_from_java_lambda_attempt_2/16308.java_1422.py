Here is the equivalent Python code:

```Python
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
```

Please note that Python does not have a direct equivalent of Java's `try-with-resources` statement. Instead, we use try-except blocks to handle exceptions and ensure resources are properly closed.

Also, the `Files.copy()` method in Java is replaced with the `urlretrieve()` function from the urllib library in Python, which downloads files from URLs. The destination path and file name are constructed using the os.path.join() function.