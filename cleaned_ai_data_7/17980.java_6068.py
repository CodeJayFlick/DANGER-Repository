import os
import random
from datetime import datetime

class FileLoaderTest:
    def __init__(self):
        self.data_dir = None
        self.file_loader = None
        self.prev_virtual_partition_num = 0
        self.logger = Logger()

    @classmethod
    def get_receiver_folder_file(cls, data_dir):
        return os.path.join(data_dir, '127.0.0.1_5555')

    @classmethod
    def get_snapshot_folder(cls, receiver_folder_file):
        return os.path.join(receiver_folder_file, SyncConstant.RECEIVER_DATA_FOLDER_NAME)

    @classmethod
    def from_time_to_time_partition(cls, time):
        partition_interval = IoTDBDescriptor.getInstance().getConfig().getPartitionInterval()
        return int(time / partition_interval)

    @before
    def setup(self):
        self.prev_virtual_partition_num = IoTDBDescriptor.getInstance().getConfig().getVirtualStorageGroupNum()
        IoTDBDescriptor.getInstance().getConfig().setVirtualStorageGroupNum(1)
        IoTDBDescriptor.getInstance().getConfig().setSyncEnable(True)
        EnvironmentUtils.closeStatMonitor()
        EnvironmentUtils.envSetUp()
        self.data_dir = os.path.join(DirectoryManager.getInstance().getNextFolderForSequenceFile())
        try:
            init_metadata()
        except MetadataException as e:
            print(f"Error initializing metadata: {e}")

    def init_metadata(self):
        m_manager = IoTDB.metaManager
        m_manager.init()
        for i in range(3):
            m_manager.set_storage_group(PartialPath("root.sg{}".format(i)))

    @after
    def tearDown(self):
        EnvironmentUtils.cleanEnv()
        IoTDBDescriptor.getInstance().getConfig().setSyncEnable(False)
        IoTDBDescriptor.getInstance().getConfig().setVirtualStorageGroupNum(self.prev_virtual_partition_num)

    @test
    def load_new_tsfiles(self):
        self.file_loader = FileLoader.create_file_loader(self.get_receiver_folder_file())
        all_files_list = {}
        correct_sequence_loaded_file_map = {}

        for i in range(3):
            for j in range(10):
                sg_name = "root.sg{}".format(i)
                if not sg_name in all_files_list:
                    all_files_list[sg_name] = []
                    correct_sequence_loaded_file_map[sg_name] = set()
                rand_str = str(random.randint(0, 10000))
                file_name = os.path.join(self.get_snapshot_folder(), "0", "0", "{}.tsfile".format(datetime.now().timestamp() + i * 100 + j), rand_str)
                sync_file = File(file_name)
                data_file = os.path.join(DirectoryManager.getInstance().getNextFolderForSequenceFile(), sg_name, str(j))
                correct_sequence_loaded_file_map[sg_name].add(data_file)
                all_files_list[sg_name].append(sync_file)

        for i in range(3):
            processor = StorageEngine.getInstance().get_processor(PartialPath("root.sg{}".format(i)))
            self.assertTrue(processor.get_sequence_file_tree_set().empty())
            self.assertTrue(processor.get_unsequence_file_list().empty())

        self.assertTrue(self.get_receiver_folder_file().exists())
        for files in all_files_list.values():
            for file in files:
                if not file.name.endswith(TsFileResource.RESOURCE_SUFFIX):
                    self.file_loader.add_tsfile(file)

        self.file_loader.end_sync()

        try:
            wait_time = 0
            while FileLoaderManager.getInstance().contains_file_loader(self.get_receiver_folder_file()):
                time.sleep(100)
                wait_time += 100
                print(f"Has waited for loading new tsfiles {wait_time}ms")
        except InterruptedException as e:
            self.logger.error("Fail to wait for loading new tsfiles", e)

        self.assertFalse(os.path.exists(os.path.join(self.get_receiver_folder_file(), SyncConstant.RECEIVER_DATA_FOLDER_NAME)))
        sequence_loaded_file_map = {}
        for i in range(3):
            processor = StorageEngine.getInstance().get_processor(PartialPath("root.sg{}".format(i)))
            sequence_loaded_file_map[sg_name] = set()
            self.assertEqual(len(processor.get_sequence_file_tree_set()), 10)
            for tsfile_resource in processor.get_sequence_file_tree_set():
                sequence_loaded_file_map[sg_name].add(tsfile_resource.ts_file.path)

        self.assertEqual(len(sequence_loaded_file_map), len(correct_sequence_loaded_file_map))
        for sg, files in correct_sequence_loaded_file_map.items():
            self.assertEqual(len(files), len(sequence_loaded_file_map[sg]))

    @test
    def load_deleted_filename(self):
        self.file_loader = FileLoader.create_file_loader(self.get_receiver_folder_file())
        all_files_list = {}
        correct_loaded_file_map = {}

        for i in range(3):
            for j in range(25):
                sg_name = "root.sg{}".format(i)
                if not sg_name in all_files_list:
                    all_files_list[sg_name] = []
                    correct_loaded_file_map[sg_name] = set()
                rand_str = str(random.randint(0, 10000))
                file_name = os.path.join(self.get_snapshot_folder(), "0", "0", "{}.tsfile".format(datetime.now().timestamp() + i * 100 + j), rand_str)
                sync_file = File(file_name)
                data_file = os.path.join(DirectoryManager.getInstance().getNextFolderForSequenceFile(), sg_name, str(j))
                correct_loaded_file_map[sg_name].add(data_file)
                all_files_list[sg_name].append(sync_file)

        for i in range(3):
            processor = StorageEngine.getInstance().get_processor(PartialPath("root.sg{}".format(i)))
            self.assertTrue(processor.get_sequence_file_tree_set().empty())
            self.assertTrue(processor.get_unsequence_file_list().empty())

        self.assertTrue(self.get_receiver_folder_file().exists())
        for files in all_files_list.values():
            for file in files:
                if not file.name.endswith(TsFileResource.RESOURCE_SUFFIX):
                    self.file_loader.add_tsfile(file)

        self.file_loader.end_sync()

        try:
            wait_time = 0
            while FileLoaderManager.getInstance().contains_file_loader(self.get_receiver_folder_file()):
                time.sleep(100)
                wait_time += 100
                print(f"Has waited for loading new tsfiles {wait_time}ms")
        except InterruptedException as e:
            self.logger.error("Fail to wait for loading new tsfiles", e)

        self.assertFalse(os.path.exists(os.path.join(self.get_receiver_folder_file(), SyncConstant.RECEIVER_DATA_FOLDER_NAME)))
        loaded_file_map = {}
        for i in range(3):
            processor = StorageEngine.getInstance().get_processor(PartialPath("root.sg{}".format(i)))
            loaded_file_map[sg_name] = set()
            self.assertEqual(len(processor.get_sequence_file_tree_set()), 25)
            for tsfile_resource in processor.get_sequence_file_tree_set():
                loaded_file_map[sg_name].add(tsfile_resource.ts_file.path)

        self.assertEqual(len(loaded_file_map), len(correct_loaded_file_map))
        for sg, files in correct_loaded_file_map.items():
            self.assertEqual(len(files), len(loaded_file_map[sg]))

        # delete some tsfiles
        deleted_files = []
        for entry in all_files_list.items():
            sg_name = entry[0]
            files = entry[1]
            cnt = 0
            for file in files:
                if not file.name.endswith(TsFileResource.RESOURCE_SUFFIX):
                    data_file = os.path.join(DirectoryManager.getInstance().getNextFolderForSequenceFile(), sg_name, str(cnt))
                    correct_loaded_file_map[sg_name].remove(data_file)
                    file.delete()
                    deleted_files.append(file)
                    new_file_path = "{}{}".format(file.name, TsFileResource.RESOURCE_SUFFIX)
                    if os.path.exists(new_file_path):
                        os.remove(new_file_path)
                    cnt += 1
                if cnt == 15:
                    break

        self.file_loader.end_sync()

        try:
            wait_time = 0
            while FileLoaderManager.getInstance().contains_file_loader(self.get_receiver_folder_file()):
                time.sleep(100)
                wait_time += 100
                print(f"Has waited for loading new tsfiles {wait_time}ms")
        except InterruptedException as e:
            self.logger.error("Fail to wait for loading new tsfiles", e)

        loaded_file_map.clear()
        for i in range(3):
            processor = StorageEngine.getInstance().get_processor(PartialPath("root.sg{}".format(i)))
            loaded_file_map[sg_name] = set()
            for tsfile_resource in processor.get_sequence_file_tree_set():
                loaded_file_map[sg_name].add(tsfile_resource.ts_file.path)

        self.assertEqual(len(loaded_file_map), len(correct_loaded_file_map))
        for sg, files in correct_loaded_file_map.items():
            self.assertTrue(files.issuperset(loaded_file_map[sg]))
