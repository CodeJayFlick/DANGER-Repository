Here is the translation of the Java code into Python:

```Python
import os
import random
from typing import Dict, Any

class SyncFileManagerTest:
    def __init__(self):
        self.logger = LoggerFactory.getLogger(SyncFileManagerTest)
        self.manager = SyncFileManager.getInstance()
        self.config = SyncSenderDescriptor.getInstance().getConfig()
        self.data_dir = None

    @classmethod
    def setUp(cls) -> None:
        EnvironmentUtils.envSetUp()

    @classmethod
    def tearDown(cls) -> None:
        EnvironmentUtils.cleanEnv()

    def test_get_valid_files(self):
        all_file_list: Dict[str, Dict[long, Dict[long, set]]] = {}
        random.seed(0)
        for i in range(3):
            sg_name = self.get_sg_name(i)
            IoTDB.meta_manager.set_storage_group(PartialPath(sg_name))
            for j in range(5):
                all_file_list.setdefault(sg_name, {})[0][0].add(self.create_random_file())
        manager.get_valid_files(data_dir)

    def test_get_valid_files_with_invalid_files(self):
        random.seed(3)
        for i in range(3):
            sg_name = self.get_sg_name(i)
            for j in range(5):
                all_file_list.setdefault(sg_name, {})[0][0].add(self.create_random_file())
        manager.get_valid_files(data_dir)

    def test_get_valid_files_with_deleted_files(self):
        random.seed(2)
        deleted_files_map = {}
        to_be_synced_files_map = {}
        for i in range(3):
            sg_name = self.get_sg_name(i)
            all_file_list.setdefault(sg_name, {})[0][0].add(self.create_random_file())
            deleted_files_map.setdefault(sg_name, {})[0][0].add(self.create_random_file())

    def create_random_file(self) -> str:
        random_number = str(random.randint(10000))
        file_path = os.path.join(data_dir, IoTDBConstant.SEQUENCE_FOLDER_NAME, sg_name)
        return f"{file_path}/{random_number}{TSFILE_SUFFIX}"

    @classmethod
    def get_sg_name(cls, i: int):
        return f"{IoTDBConstant.PATH_ROOT}/{IoTDBConstant.PATH_SEPARATOR}/{i}"
```

Note that this is a direct translation of the Java code into Python. It's not optimized for performance or readability in Python terms.