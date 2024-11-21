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
