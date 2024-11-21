import logging
from typing import Dict, List

class UpgradeUtils:
    _logger = logging.getLogger(__name__)
    _COMMA_SEPERATOR = ","
    
    def __init__(self):
        self._upgrade_recover_map: Dict[str, int] = {}
        
    @property
    def cnt_upgrade_file_lock(self) -> object:
        return self._cnt_upgrade_file_lock
    
    @property
    def upgrade_log_lock(self) -> object:
        return self._upgrade_log_lock

    _fs_factory = None  # type: FSFactory
    _cnt_upgrade_file_lock = None  # type: ReadWriteLock
    _upgrade_log_lock = None  # type: ReadWriteLock
    
    @property
    def fs_factory(self) -> 'FSFactory':
        if self._fs_factory is None:
            from your_module import FSFactoryProducer, TSFileConfig
            self._fs_factory = FSFactoryProducer().get_fs_factory()
        return self._fs_factory

    def get_cnt_upgrade_file_lock(self):
        return self._cnt_upgrade_file_lock
    
    def get_upgrade_log_lock(self):
        return self._upgrade_log_lock

    @staticmethod
    def is_need_upgrade(tsfile_resource: 'TsFileResource') -> bool:
        tsfile_resource.read_lock()
        
        try:
            if tsfile_resource.get_tsfile().length() == 0:
                return False
            
            from your_module import TsFileSequenceReaderForV2, TSFileConfig
            reader = TsFileSequenceReaderForV2(tsfile_resource.get_tsfile().getAbsolutePath())
            version_number = reader.read_version_number_v2()
            
            if version_number in [TSFileConfig.VERSION_NUMBER_V2, TSFileConfig.VERSION_NUMBER_V1]:
                return True
        
        except IOException as e:
            UpgradeUtils._logger.error("meet error when judge whether file needs to be upgraded, the file's path:{}", tsfile_resource.get_tsfile().getAbsolutePath(), e)
        
        finally:
            tsfile_resource.read_unlock()
        
        return False

    @staticmethod
    def move_upgraded_files(resource: 'TsFileResource') -> None:
        from your_module import TSFileConfig
        
        upgraded_resources = resource.get_upgraded_resources()
        
        for upgraded_resource in upgraded_resources:
            file_path = upgraded_resource.get_tsfile().getAbsolutePath()
            
            partition = upgraded_resource.get_time_partition()
            virtual_storage_group_dir = os.path.dirname(os.path.dirname(file_path))
            partition_dir = UpgradeUtils.fs_factory.get_file(virtual_storage_group_dir, str(partition))
            
            if not partition_dir.exists():
                partition_dir.mkdir()
            
            # move upgraded TsFile
            file_name = os.path.basename(file_path)
            temp_resource_file = f"{file_path}{TSFileConfig.RESOURCE_SUFFIX}"
            new_mods_file = f"{file_path}{ModificationFile.FILE_SUFFIX}"
            
            if os.path.exists(temp_resource_file):
                UpgradeUtils.fs_factory.move_file(temp_resource_file, partition_dir / file_name)
            
            # move upgraded mods file
            if os.path.exists(new_mods_file):
                UpgradeUtils.fs_factory.move_file(new_mods_file, partition_dir / new_mods_file.name)
            
            # re-serialize upgraded resource to correct place
            upgraded_resource.set_file(partition_dir / file_name)
            upgraded_resource.get_mod_file()
            upgraded_resource.serialize()
            
            # delete generated temp resource file
            os.remove(temp_resource_file)

    @staticmethod
    def is_upgraded_file_generated(old_file_name: str) -> bool:
        return old_file_name in UpgradeUtils._upgrade_recover_map and UpgradeUtils._upgrade_recover_map[old_file_name] == UpgradeCheckStatus.AFTER_UPGRADE_FILE.get_check_status_code()

    @classmethod
    def clear_upgrade_recover_map(cls):
        cls._upgrade_recover_map = None

    @staticmethod
    def recover_upgrade():
        from your_module import FSFactoryProducer, TSFileConfig
        
        if os.path.exists(FSFactoryProducer().get_fs_factory().get_file(TSFileConfig.UPGRADE_LOG_PATH)):
            try:
                with open(FSFactoryProducer().get_fs_factory().get_file(TSFileConfig.UPGRADE_LOG_PATH), 'r') as file:
                    for line in file.readlines():
                        old_file_path = line.split(UpgradeUtils._COMMA_SEPERATOR)[0]
                        old_file_name = os.path.basename(old_file_path)
                        
                        if UpgradeUtils._upgrade_recover_map.get(old_file_name):
                            UpgradeUtils._upgrade_recover_map[old_file_name] += 1
                        else:
                            UpgradeUtils._upgrade_recover_map[old_file_name] = 1
            
            except Exception as e:
                UpgradeUtils._logger.error("meet error when recover upgrade process, file path:{}", TSFileConfig.UPGRADE_LOG_PATH, e)
            
            finally:
                os.remove(FSFactoryProducer().get_fs_factory().get_file(TSFileConfig.UPGRADE_LOG_PATH))
