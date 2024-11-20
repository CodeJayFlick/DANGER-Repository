import os
import random
from typing import Dict, Set

class SyncSenderLogAnalyzerTest:
    def __init__(self):
        self.logger = None  # ISyncSenderLogger type
        self.sender_log_analyzer = None  # ISyncSenderLogAnalyzer type
        self.manager = None  # ISyncFileManager type
        self.config = None  # SyncSenderConfig type
        self.data_dir = None

    def setUp(self):
        os.makedirs('data', exist_ok=True)
        data_dir = 'data'
        config.update(data_dir)
        sender_logger = SyncSenderLogger(os.path.join(config.get_sender_folder_path(), 'sync.log'))
        sender_log_analyzer = SyncSenderLogAnalyzer(config.get_sender_folder_path())
        self.logger = sender_logger
        self.sender_log_analyzer = sender_log_analyzer

    def tearDown(self):
        os.rmdir('data')

    def recover(self) -> None:
        all_file_list: Dict[str, Dict[long, Dict[long, Set[File]]]] = {}
        
        for i in range(3):
            IoTDB.meta_manager.set_storage_group(PartialPath(f"sg_{i}"))
            
        random.seed(0)
        for i in range(3):
            for j in range(5):
                all_file_list.setdefault(f"sg_{i}", {}).setdefault(0, {})[0][random.randint(1, 10000)] = True
                file_name = os.path.join(data_dir, f"sequence_folder", f"{get_sg_name(i)}", "0", "0", str(random.randint(1, 10000)) + '.tsfile')
                all_file_list[f"sg_{i}"][0][random.randint(1, 10000)].add(file_name)
                
        manager.get_valid_files(data_dir)
        self.assertTrue(SyncUtils.is_empty(manager.last_local_files_map))
        
        sender_logger.start_sync_tsfiles()
        for file_list in all_file_list.values():
            for vg_map in file_list.values():
                for new_ts_files in vg_map.values():
                    for file in new_ts_files:
                        sender_logger.finish_sync_tsfile(file)
                        
        self.logger.close()

    def recover_log(self) -> None:
        self.sender_log_analyzer.recover()
        
    # rest of the code remains same
