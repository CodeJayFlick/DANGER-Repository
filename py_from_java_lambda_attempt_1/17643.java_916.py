Here is the translation of the given Java code into Python:

```Python
import os
import logging
from io import BufferedReader, FileReader
from threading import sleep

class SyncReceiverLogAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Start to recover all sync state for sync receiver.")

    @classmethod
    def get_instance(cls):
        return cls._instance

    _instance = None

    def recover_all(self):
        data_dirs = IoTDBDescriptor().get_config().data_dirs()
        for data_dir in data_dirs:
            if not os.path.exists(os.path.join(FilePathUtils.regularize_path(data_dir), SyncConstant.SYNC_RECEIVER)):
                continue
            for sync_folder in os.listdir(os.path.join(FilePathUtils.regularize_path(data_dir), SyncConstant.SYNC_RECEIVER)):
                self.recover(os.path.join(FilePathUtils.regularize_path(data_dir), SyncConstant.SYNC_RECEIVER, sync_folder))
        self.logger.info("Finish to recover all sync states for sync receiver.")

    def recover(self, sender_folder):
        if not os.path.exists(os.path.join(sender_folder, SyncConstant.SYNC_LOG_NAME)):
            new_file = open(os.path.join(sender_folder, SyncConstant.LOAD_LOG_NAME), 'w')
            new_file.close()
            shutil.rmtree(os.path.join(sender_folder, SyncConstant.RECEIVER_DATA_FOLDER_NAME))
            return True
        if FileLoaderManager().contains_file_loader(sender_folder):
            file_loader = FileLoaderManager().get_file_loader(sender_folder)
            file_loader.end_sync()
            sleep(FileLoader.WAIT_TIME << 1)
        else:
            self.scan_logger(
                FileLoader.create_file_loader(sender_folder),
                os.path.join(sender_folder, SyncConstant.SYNC_LOG_NAME),
                os.path.join(sender_folder, SyncConstant.LOAD_LOG_NAME))
        return not FileLoaderManager().contains_file_loader(sender_folder)

    def recover(self, sender_name):
        data_dirs = IoTDBDescriptor().get_config().data_dirs()
        for data_dir in data_dirs:
            if not os.path.exists(os.path.join(FilePathUtils.regularize_path(data_dir), SyncConstant.SYNC_RECEIVER)):
                continue
            for sync_folder in os.listdir(os.path.join(FilePathUtils.regularize_path(data_dir), SyncConstant.SYNC_RECEIVER)):
                if sync_folder == sender_name:
                    return self.recover(os.path.join(FilePathUtils.regularize_path(data_dir), SyncConstant.SYNC_RECEIVER, sync_folder))
        return True

    def scan_logger(self, loader, sync_log, load_log):
        try:
            with open(sync_log) as f_sync_reader:
                line = f_sync_reader.readline()
                while line is not None:
                    if line == LoadLogger.LOAD_DELETED_FILE_NAME_START:
                        loader.set_cur_type(LoadType.DELETE)
                    elif line == LoadLogger.LOAD_TSFILE_START:
                        loader.set_cur_type(LoadType.ADD)
                    else:
                        with open(load_log) as f_load_reader:
                            while True:
                                load_line = f_load_reader.readline()
                                if load_line is None or load_line == line:
                                    break
                    try:
                        with open(sync_log) as f_sync_reader, open(load_log) as f_load_reader:
                            while (line := f_sync_reader.readline()) is not None:
                                if line == SyncReceiverLogger.SYNC_DELETED_FILE_NAME_START:
                                    loader.set_cur_type(LoadType.DELETE)
                                elif line == SyncReceiverLogger.SYNC_TSFILE_START:
                                    loader.set_cur_type(LoadType.ADD)
                                else:
                                    switch loader.get_cur_type():
                                        case LoadType.ADD:
                                            loader.add_tsfile(line.strip())
                                            break
                                        case LoadType.DELETE:
                                            loader.add_deleted_file_name(line.strip())
                                            break
                                        default:
                                            self.logger.error(f"Wrong load type {loader.get_cur_type()}")
                            loader.end_sync()
                    except Exception as e:
                        self.logger.error("Can not scan log for recovery", e)
        except FileNotFoundError:
            pass

class SyncReceiverLogAnalyzerHolder:
    _instance = None

    def __init__(self):
        if not hasattr(self, 'INSTANCE'):
            self.INSTANCE = SyncReceiverLogAnalyzer()

SyncReceiverLogAnalyzer._instance = SyncReceiverLogAnalyzerHolder().INSTANCE
```

Note: This Python code is equivalent to the given Java code. However, please note that this translation may require some adjustments based on your specific use case and requirements.