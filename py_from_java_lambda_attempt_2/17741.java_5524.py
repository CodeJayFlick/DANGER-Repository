Here is the translation of the Java code into Python:

```Python
import unittest
from unittest.mock import patch, mock_static
from io import IOError

class DirectoryStrategyTest(unittest.TestCase):

    def setUp(self):
        self.data_dir_list = []
        for i in range(5):
            self.data_dir_list.append(f"OUTPUT_DATA_DIR{i}")
        
        full_dir_index_set = set()
        full_dir_index_set.add(1)
        full_dir_index_set.add(3)

        with patch('org.apache.iotdb.db.utils.CommonUtils', autospec=True) as common_utils:
            for i in range(len(self.data_dir_list)):
                if not full_dir_index_set.contains(i):
                    common_utils.has_space.return_value = True
                    common_utils.get_usable_space.return_value = i + 1
                    common_utils.get_occupied_space.return_value = i + 1
                else:
                    common_utils.has_space.return_value = False
                    common_utils.get_usable_space.return_value = 0L
                    common_utils.get_occupied_space.return_value = long.max_value

    def tearDown(self):
        pass

    @patch('org.apache.iotdb.db.utils.CommonUtils', autospec=True)
    def test_sequence_strategy(self, mock_common_utils):
        sequence_strategy = SequenceStrategy()
        sequence_strategy.set_folders(self.data_dir_list)

        index = 0
        for _ in range(len(self.data_dir_list) * 2):
            if full_dir_index_set.contains(index % len(self.data_dir_list)):
                index += 1
            self.assertEqual(sequence_strategy.next_folder_index(), index)
            index = (index + 1) % len(self.data_dir_list)

    @patch('org.apache.iotdb.db.utils.CommonUtils', autospec=True)
    def test_max_disk_usable_space_first_strategy(self, mock_common_utils):
        max_disk_usable_space_first_strategy = MaxDiskUsableSpaceFirstStrategy()
        max_disk_usable_space_first_strategy.set_folders(self.data_dir_list)

        index = get_index_of_max_space()

        for _ in range(len(self.data_dir_list)):
            self.assertEqual(max_disk_usable_space_first_strategy.next_folder_index(), index)
        
        mock_common_utils.get_usable_space.return_value = 0L
        max_disk_usable_space_first_strategy.set_folders(self.data_dir_list)

    @patch('org.apache.iotdb.db.utils.CommonUtils', autospec=True)
    def test_min_folder_occupied_space_first_strategy(self, mock_common_utils):
        min_folder_occupied_space_first_strategy = MinFolderOccupiedSpaceFirstStrategy()
        min_folder_occupied_space_first_strategy.set_folders(self.data_dir_list)

        index = get_index_of_min_occupied_space()

        for _ in range(len(self.data_dir_list)):
            self.assertEqual(min_folder_occupied_space_first_strategy.next_folder_index(), index)
        
        mock_common_utils.get_occupied_space.return_value = long.max_value
        min_folder_occupied_space_first_strategy.set_folders(self.data_dir_list)

    @patch('org.apache.iotdb.db.utils.CommonUtils', autospec=True)
    def test_random_on_disk_usable_space_strategy(self, mock_common_utils):
        random_on_disk_usable_space_strategy = RandomOnDiskUsableSpaceStrategy()
        random_on_disk_usable_space_strategy.set_folders(self.data_dir_list)

        for _ in range(len(self.data_dir_list)):
            self.assertFalse(full_dir_index_set.contains(random_on_disk_usable_space_strategy.next_folder_index()))
        
        new_full_index = random_on_disk_usable_space_strategy.next_folder_index()
        mock_common_utils.get_usable_space.return_value = 0L
        for _ in range(len(self.data_dir_list)):
            index = random_on_disk_usable_space_strategy.next_folder_index()
            self.assertFalse(full_dir_index_set.contains(index))
            self.assertNotEqual(new_full_index, index)

    @patch('org.apache.iotdb.db.utils.CommonUtils', autospec=True)
    def test_all_disk_full(self, mock_common_utils):
        for i in range(len(self.data_dir_list)):
            mock_common_utils.has_space.return_value = False

        sequence_strategy = SequenceStrategy()
        try:
            sequence_strategy.set_folders(self.data_dir_list)
            self.fail()
        except IOError:
            pass
        
        max_disk_usable_space_first_strategy = MaxDiskUsableSpaceFirstStrategy()
        try:
            max_disk_usable_space_first_strategy.set_folders(self.data_dir_list)
            self.fail()
        except IOError:
            pass
        
        min_folder_occupied_space_first_strategy = MinFolderOccupiedSpaceFirstStrategy()
        try:
            min_folder_occupied_space_first_strategy.set_folders(self.data_dir_list)
            self.fail()
        except IOError:
            pass

def get_index_of_max_space():
    index = -1
    max_space = long.max_value
    for i in range(len(data_dir_list)):
        space = mock_common_utils.get_usable_space.return_value
        if max_space < space:
            index = i
            max_space = space
    return index

def get_index_of_min_occupied_space():
    index = -1
    min_occupied = long.max_value
    for i in range(len(data_dir_list)):
        space = mock_common_utils.get_occupied_space.return_value
        if min_occupied > space:
            index = i
            min_occupied = space
    return index

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect, and you might need to adjust it according to your specific requirements.