import os
from collections import defaultdict

class SyncFileManager:
    def __init__(self):
        self.all_sgs = {}
        self.current_sealed_local_files_map = {}
        self.last_local_files_map = {}
        self.deleted_files_map = {}
        self.to_be_synced_files_map = {}

    @staticmethod
    def get_instance():
        return SyncFileManagerHolder.INSTANCE

    def getCurrentLocalFiles(self, data_dir):
        logger.info("Start to get current local files in data folder: {}".format(data_dir))

        for sg_folder in os.listdir(os.path.join(data_dir, IoTDBConstant.SEQUENCE_FOLDER_NAME)):
            if not sg_folder.startswith(IoTDBConstant.PATH_ROOT) or sg_folder == TsFileConstant.TMP_SUFFIX:
                continue

            self.all_sgs[sg_folder] = {}
            current_all_local_files_map = defaultdict(dict)

            for virtual_sg_folder in os.listdir(os.path.join(data_dir, IoTDBConstant.SEQUENCE_FOLDER_NAME, sg_folder)):
                try:
                    vg_id = int(virtual_sg_folder)
                    self.all_sgs[sg_folder][vg_id] = set()
                    current_all_local_files_map[sg_folder][vg_id] = defaultdict(set)

                    for time_range_folder in os.listdir(os.path.join(data_dir, IoTDBConstant.SEQUENCE_FOLDER_NAME, sg_folder, virtual_sg_folder)):
                        try:
                            time_range_id = int(time_range_folder)
                            files = [os.path.join(virtual_sg_folder, time_range_folder, file) for file in os.listdir(os.path.join(data_dir, IoTDBConstant.SEQUENCE_FOLDER_NAME, sg_folder, virtual_sg_folder, time_range_folder))]

                            current_all_local_files_map[sg_folder][vg_id][time_range_id].update(files)
                        except Exception as e:
                            logger.error("Invalid virtual storage group folder: {}".format(virtual_sg_folder), e)

                except Exception as e:
                    logger.error("Invalid virtual storage group folder: {}".format(sg_folder), e)

            self.current_sealed_local_files_map = {sg_name: dict((vg_id, dict((time_range_id, set(files)) for time_range_id, files in current_all_local_files[vg_id].items())) for vg_id, current_all_local_files in current_all_local_files_map[sg_name].items()) for sg_name, _ in self.all_sgs.items()}

    def getLastLocalFiles(self, last_local_file_info):
        logger.info("Start to get last local files from last local file info: {}".format(last_local_file_info))

        if not os.path.exists(last_local_file_info):
            return

        try:
            with open(last_local_file_info) as f:
                for line in f.readlines():
                    file_path = line.strip()
                    time_range_id = int(os.path.dirname(file_path))
                    vg_id = int(os.path.dirname(os.path.dirname(file_path)))
                    sg_name = os.path.dirname(os.path.dirname(os.path.dirname(file_path)))

                    if not self.all_sgs.get(sg_name):
                        self.all_sgs[sg_name] = {}
                    if not self.all_sggs[sg_name].get(vg_id):
                        self.all_sgss[sg_name][vg_id] = set()
                    self.last_local_files_map.setdefault(sg_name, {})[vg_id].setdefault(time_range_id, set()).add(file_path)
        except Exception as e:
            logger.error("Error reading last local file info: {}".format(last_local_file_info), e)

    def getValidFiles(self, data_dir):
        self.getCurrentLocalFiles(data_dir)
        self.getLastLocalFiles( SyncSenderDescriptor.get_instance().get_config().getLastFileInfoPath())
        self.to_be_synced_files_map = defaultdict(dict)
        self.deleted_files_map = defaultdict(dict)

        for sg_name in self.all_sgss:
            to_be_synced_files_map[sg_name] = {}
            deleted_files_map[sg_name] = {}

            for vg_id, current_sealed_local_files in self.current_sealed_local_files_map.get(sg_name, {}).items():
                time_range_id = int(list(current_sealed_local_files.keys())[0])
                to_be_synced_files_map[sg_name][vg_id].setdefault(time_range_id, set())

                if not last_local_files_map.get(sg_name).get(vg_id):
                    continue

                for old_file in list(last_local_files_map[sg_name][vg_id][time_range_id]):
                    if current_sealed_local_files[time_range_id].remove(old_file):
                        deleted_files_map[sg_name][vg_id].setdefault(time_range_id, set()).add(old_file)

    def getCurrentSealedLocalFilesMap(self):
        return self.current_sealed_local_files_map

    def getLastLocalFilesMap(self):
        return self.last_local_files_map

    def getDeletedFilesMap(self):
        return self.deleted_files_map

    def getToBeSyncedFilesMap(self):
        return self.to_be_synced_files_map

    def getAllSGs(self):
        return self.all_sgss


class SyncFileManagerHolder:
    INSTANCE = SyncFileManager()

    __init__ = lambda self: None
