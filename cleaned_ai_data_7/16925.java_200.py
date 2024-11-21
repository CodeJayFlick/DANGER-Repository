import logging
from abc import ABCMeta, abstractmethod
import os
import sys

class DirectoryManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sequence_file_folders = []
        self.unsequence_file_folders = []
        self.sequence_strategy = None
        self.unsequence_strategy = None
        
        sequence_file_folders = IoTDBDescriptor.getInstance().getConfig().getDataDirs()
        for i in range(len(sequence_file_folders)):
            folder = os.path.join(sequence_file_folders[i], 'SEQUENCE_FOLDER_NAME')
            if not os.path.exists(folder):
                try:
                    os.makedirs(folder)
                    self.logger.info(f"Folder {folder} doesn't exist, created it")
                except Exception as e:
                    self.logger.error(f"Failed to create folder {folder}, error: {e}")
            else:
                self.logger.info(f"Folder {folder} already exists")

        unsequence_file_folders = IoTDBDescriptor.getInstance().getConfig().getDataDirs()
        for i in range(len(unsequence_file_folders)):
            folder = os.path.join(unsequence_file_folders[i], 'UNSEQUENCE_FOLDER_NAME')
            if not os.path.exists(folder):
                try:
                    os.makedirs(folder)
                    self.logger.info(f"Folder {folder} doesn't exist, created it")
                except Exception as e:
                    self.logger.error(f"Failed to create folder {folder}, error: {e}")
            else:
                self.logger.info(f"Folder {folder} already exists")

        strategy_name = IoTDBDescriptor.getInstance().getConfig().getMultiDirStrategyClassName()
        try:
            clazz = type(strategy_name)
            instance = clazz()
            self.sequence_strategy = instance
            self.unsequence_strategy = instance
            for folder in sequence_file_folders:
                self.sequence_strategy.set_folder(os.path.join(folder, 'SEQUENCE_FOLDER_NAME'))
            for folder in unsequence_file_folders:
                self.unsequence_strategy.set_folder(os.path.join(folder, 'UNSEQUENCE_FOLDER_NAME'))
        except Exception as e:
            self.logger.error(f"Failed to create strategy {strategy_name} for mult-directories, error: {e}")

    def update_file_folders(self):
        try:
            sequence_file_folders = IoTDBDescriptor.getInstance().getConfig().getDataDirs()
            unsequence_file_folders = IoTDBDescriptor.getInstance().getConfig().getDataDirs()

            for folder in sequence_file_folders:
                if not os.path.exists(os.path.join(folder, 'SEQUENCE_FOLDER_NAME')):
                    try:
                        os.makedirs(os.path.join(folder, 'SEQUENCE_FOLDER_NAME'))
                        self.logger.info(f"Folder {os.path.join(folder, 'SEQUENCE_FOLDER_NAME')} doesn't exist, created it")
                    except Exception as e:
                        self.logger.error(f"Failed to create folder {os.path.join(folder, 'SEQUENCE_FOLDER_NAME')}, error: {e}")
                else:
                    self.logger.info(f"Folder {os.path.join(folder, 'SEQUENCE_FOLDER_NAME')} already exists")

            for folder in unsequence_file_folders:
                if not os.path.exists(os.path.join(folder, 'UNSEQUENCE_FOLDER_NAME')):
                    try:
                        os.makedirs(os.path.join(folder, 'UNSEQUENCE_FOLDER_NAME'))
                        self.logger.info(f"Folder {os.path.join(folder, 'UNSEQUENCE_FOLDER_NAME')} doesn't exist, created it")
                    except Exception as e:
                        self.logger.error(f"Failed to create folder {os.path.join(folder, 'UNSEQUENCE_FOLDER_NAME')}, error: {e}")
                else:
                    self.logger.info(f"Folder {os.path.join(folder, 'UNSEQUENCE_FOLDER_NAME')} already exists")

            for i in range(len(sequence_file_folders)):
                self.sequence_strategy.set_folder(os.path.join(sequence_file_folders[i], 'SEQUENCE_FOLDER_NAME'))
            for i in range(len(unsequence_file_folders)):
                self.unsequence_strategy.set_folder(os.path.join(unsequence_file_folders[i], 'UNSEQUENCE_FOLDER_NAME'))

        except Exception as e:
            self.logger.error(f"Failed to update file folders, error: {e}")

    def get_next_folder_for_sequence_file(self):
        return os.path.join(sequence_file_folders[0], 'SEQUENCE_FOLDER_NAME')

    def get_unsequence_file_folder(self, index):
        return unsequence_file_folders[index]

    @staticmethod
    def getInstance():
        if not hasattr(DirectoryManager, "instance"):
            DirectoryManager.instance = DirectoryManager()
        return DirectoryManager.instance

# Usage:
if __name__ == "__main__":
    dir_manager = DirectoryManager.getInstance()
