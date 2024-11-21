Here is the equivalent Python code:

```Python
import logging
import os
import pathlib

logging.basicConfig(level=logging.WARNING)

class FileUtils:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def delete_directory(folder: pathlib.Path) -> None:
        if folder.is_dir():
            for file in folder.iterdir():
                FileUtils.delete_directory(file)
        try:
            os.remove(str(folder))
        except (FileNotFoundError, OSError) as e:
            self.logger.warning(f"{e}: {', '.join(map(str, folder.glob('**/*')))}")
```

Note that Python does not have direct equivalents for Java's `Logger` and `Files`. Instead, we use the built-in `logging` module to handle logging. The equivalent of Java's `File` class is Python's `pathlib.Path`, which provides similar functionality.

Also note that in Python, you don't need a separate method just to delete files recursively like you do in Java. You can simply iterate over all items in the directory and call your function on each item (file or subdirectory) using recursion or iteration.