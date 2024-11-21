import logging
from typing import List
import os
import shutil

class UpgradeTask:
    def __init__(self, upgrade_resource):
        self.upgrade_resource = upgrade_resource
        self.logger = logging.getLogger(__name__)

    def run(self) -> None:
        try:
            old_ts_file_path = self.upgrade_resource.ts_file.path
            if not is_upgraded_file_generated(self.upgrade_resource.ts_file.name):
                self.logger.info(f"generate upgraded file for {self.upgrade_resource.ts_file}")
                upgraded_resources = generate_upgraded_files()
            else:
                self.logger.info(f"find upgraded file for {self.upgrade_resource.ts_file}")
                upgraded_resources = find_upgraded_files()

            self.upgrade_resource.set_upgraded_resources(upgraded_resources)
            upgrade_service().get_total_upgrade_file_num().decrement()
            self.logger.info(
                f"Upgrade completes, file path: {old_ts_file_path}, the remaining upgraded file num: {upgrade_service().get_total_upgrade_file_num()}"
            )
            if upgrade_service().get_total_upgrade_file_num() == 0:
                self.logger.info("Start delete empty tmp folders")
                clear_tmp_folders( directory_manager().get_all_sequence_file_folders(), directory_manager().get_all_unsequence_file_folders())
                upgrade_service().stop()
                self.logger.info("All files upgraded successfully!")
        except Exception as e:
            self.logger.error(f"meet error when upgrade file: {self.upgrade_resource.ts_file.path}, {e}")

    def generate_upgraded_files(self) -> List[dict]:
        self.upgrade_resource.read_lock()
        old_ts_file_path = self.upgrade_resource.ts_file.path
        upgraded_resources = []
        UpgradeLog.write_upgrade_log(f"{old_ts_file_path},{UpgradeCheckStatus.BEGIN_UPGRADE_FILE}")
        try:
            tsfile_online_upgrade_tool().upgrade_one_ts_file(self.upgrade_resource, upgraded_resources)
            UpgradeLog.write_upgrade_log(f"{old_ts_file_path},{UpgradeCheckStatus.AFTER_UPGRADE_FILE}")
        finally:
            self.upgrade_resource.read_unlock()
        return upgraded_resources

    def find_upgraded_files(self) -> List[dict]:
        self.upgrade_resource.read_lock()
        upgraded_resources = []
        old_ts_file_path = self.upgrade_resource.ts_file.path
        UpgradeLog.write_upgrade_log(f"{old_ts_file_path},{UpgradeCheckStatus.BEGIN_UPGRADE_FILE}")
        try:
            upgrade_folder = self.upgrade_resource.ts_file.parent
            for temp_partition_dir in os.listdir(upgrade_folder):
                if os.path.isdir(os.path.join(upgrade_folder, temp_partition_dir)):
                    resource = TsFileResource(fs_factory().get_file(temp_partition_dir, self.upgrade_resource.ts_file.name))
                    resource.deserialize()
                    upgraded_resources.append(resource)
        finally:
            self.upgrade_resource.read_unlock()
        UpgradeLog.write_upgrade_log(f"{old_ts_file_path},{UpgradeCheckStatus.AFTER_UPGRADE_FILE}")
        return upgraded_resources

    def clear_tmp_folders(self, folders: List[str]) -> None:
        for base_dir in folders:
            file_folder = fs_factory().get_file(base_dir)
            if not os.path.isdir(file_folder):
                continue
            for storage_group in os.listdir(file_folder):
                if not os.path.isdir(os.path.join(file_folder, storage_group)):
                    continue
                virtual_storage_group_dir = fs_factory().get_file(storage_group, "0")
                upgrade_dir = fs_factory().get_file(virtual_storage_group_dir, "upgrade")
                if upgrade_dir is None:
                    continue
                for tmp_partition_dir in os.listdir(upgrade_dir):
                    file_path = os.path.join(upgrade_dir, tmp_partition_dir)
                    try:
                        shutil.rmtree(file_path)
                    except Exception as e:
                        self.logger.error(f"Delete tmpPartitionDir {file_path} failed", e)

            # delete upgrade folder when it is empty
            if os.path.isdir(upgrade_dir):
                try:
                    shutil.rmtree(upgrade_dir)
                except Exception as e:
                    self.logger.error("Delete tmpUpgradeDir {} failed".format(upgrade_dir), e)


def directory_manager():
    pass

def fs_factory():
    pass

def upgrade_service():
    pass

def UpgradeLog():
    pass
