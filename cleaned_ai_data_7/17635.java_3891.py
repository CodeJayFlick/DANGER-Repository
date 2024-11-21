import logging
from queue import Queue
import time
import os
import shutil

class LoadTask:
    def __init__(self, file: str, load_type: int):
        self.file = file
        self.load_type = load_type

    def __str__(self) -> str:
        return f"LoadTask{{file={self.file}, type={self.load_type}}}"

class FileLoader:
    def __init__(self, sender_name: str, sync_folder_path: str):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.sender_name = sender_name
        self.sync_folder_path = sync_folder_path
        self.queue = Queue()
        self.load_log = None
        self.cur_type = 0
        self.end_sync = False

    @staticmethod
    def create_file_loader(sender_name: str, sync_folder_path: str) -> 'FileLoader':
        file_loader = FileLoader(sender_name, sync_folder_path)
        # Add the file loader to the manager and start it.
        return file_loader

    def add_deleted_filename(self, deleted_file: str):
        self.queue.put(LoadTask(deleted_file, 1))

    def add_tsfile(self, tsfile: str):
        self.queue.put(LoadTask(tsfile, 0))

    def end_sync_(self) -> None:
        if not self.end_sync and FileLoaderManager().contains_file_loader(self.sender_name):
            self.end_sync = True

    def handle_load_task(self, task: LoadTask) -> None:
        if task.load_type == 1:
            self.load_deleted_file(task.file)
        elif task.load_type == 0:
            self.load_new_tsfile(task.file)

    def load_new_tsfile(self, new_tsfile: str):
        if self.cur_type != 0:
            self.load_log.start_load_ts_files()
            self.cur_type = 1
        try:
            ts_file_resource = TsFileResource(new_tsfile)
            FileLoaderUtils().check_ts_file_resource(ts_file_resource)
            StorageEngine().load_new_tsfile_for_sync(ts_file_resource)
        except (SyncDeviceOwnerConflictException, LoadFileException, StorageEngineException):
            self.logger.error(f"Failed to load new ts file {new_tsfile}")

    def load_deleted_file(self, deleted_tsfile: str) -> None:
        if self.cur_type != 1:
            self.load_log.start_load_deleted_files()
            self.cur_type = 2
        try:
            StorageEngine().delete_tsfile_for_sync(deleted_tsfile)
        except (StorageEngineException):
            self.logger.error(f"Failed to load deleted ts file {deleted_tsfile}")

    def clean_up(self) -> None:
        if not self.end_sync:
            return

        try:
            self.load_log.close()
            os.remove(os.path.join(self.sync_folder_path, "sync.log"))
            os.remove(os.path.join(self.sync_folder_path, "load.log"))
            shutil.rmtree(os.path.join(self.sync_folder_path, "receiver_data_folder_name"))
            FileLoaderManager().remove_file_loader(self.sender_name)
        except (Exception):
            self.logger.error("Failed to clean up sync resources")

    def set_cur_type(self, cur_type: int) -> None:
        self.cur_type = cur_type

class TsFileResource:
    pass  # Implement this class as needed.

class StorageEngine:
    @staticmethod
    def load_new_tsfile_for_sync(ts_file_resource):
        pass  # Implement this method as needed.

    @staticmethod
    def delete_tsfile_for_sync(deleted_tsfile: str) -> None:
        pass  # Implement this method as needed.
