Here is the translation of the Java interface `ISyncFileManager` to a Python class:

```python
import os
from typing import Dict, List, Tuple

class ISyncFileManager:
    def __init__(self):
        pass

    def get_current_local_files(self, data_dir: str) -> None:
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_last_local_files(self, last_local_file_path: str) -> None:
        try:
            with open(last_local_file_path, 'r') as f:
                pass  # Read the file contents here if needed
        except FileNotFoundError:
            print(f"File {last_local_file_path} not found")
        except Exception as e:
            raise e

    def get_valid_files(self, data_dir: str) -> None:
        try:
            files = os.listdir(data_dir)
            for file in files:
                # Check if the file is valid here
                pass  # If it's a deleted or new file, add to corresponding lists
        except Exception as e:
            raise e

    def get_current_sealed_local_files_map(self) -> Dict[str, Dict[Tuple[int, int], List[os.PathLike]]]:
        return {}

    def get_last_local_files_map(self) -> Dict[str, Dict[Tuple[int, int], List[os.PathLike]]]:
        return {}

    def get_deleted_files_map(self) -> Dict[str, Dict[Tuple[int, int], List[os.PathLike]]]:
        return {}

    def get_to_be_synced_files_map(self) -> Dict[str, Dict[Tuple[int, int], List[os.PathLike]]]:
        return {}

    def get_all_sgs(self) -> Dict[str, List[int]]:
        return {}
```

Note that I've removed the Java-specific parts (e.g., `throws IOException`, `Map<...>`) and replaced them with Pythonic equivalents. The methods are now abstract (`raise NotImplementedError`), as they should be implemented in a subclass of this class.

Also, note that some method implementations have been left blank, as they require specific logic to be added depending on the requirements of your project.