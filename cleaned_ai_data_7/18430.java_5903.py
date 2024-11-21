import os
from unittest import TestCase


class FilePathUtilsTest(TestCase):

    storage_group_name = "root.group_9"
    virtual_sg_name = "1"
    partition_id = 0
    ts_file_name = "1611199237113-4-0.tsfile"

    def setUp(self):
        self.ts_file_path = os.path.join("target", *([self.storage_group_name, self.virtual_sg_name, str(self.partition_id)]), self.ts_file_name)
        try:
            os.makedirs(os.path.dirname(self.ts_file_path))
            with open(self.ts_file_path, 'w'):
                pass
        except Exception as e:
            self.fail(str(e))

    def test_get_logical_sg_name_and_time_partition_id_pair(self):
        sg_name_and_time_partition_id = FilePathUtils.get_logical_sg_name_and_time_partition_id_pair(os.path.abspath(self.ts_file_path))
        self.assertEqual(self.storage_group_name, sg_name_and_time_partition_id[0])
        self.assertEqual(self.partition_id, int(sg_name_and_time_partition_id[1]))

    def test_get_logical_storage_group_name(self):
        logical_sg_name = FilePathUtils.get_logical_storage_group_name(os.path.abspath(self.ts_file_path))
        self.assertEqual(self.storage_group_name, logical_sg_name)

    def test_get_virtual_storage_group_name(self):
        virtual_sg_name = FilePathUtils.get_virtual_storage_group_id(os.path.abspath(self.ts_file_path))
        self.assertEqual(self.virtual_sg_name, virtual_sg_name)

    def test_get_time_partition_id(self):
        time_partition_id = FilePathUtils.get_time_partition_id(os.path.abspath(self.ts_file_path))
        self.assertEqual(self.partition_id, int(time_partition_id))

    def test_get_ts_file_prefix_path(self):
        ts_file_prefix_path = FilePathUtils.get_ts_file_prefix_path(os.path.abspath(self.ts_file_path))
        expected_prefix_path = os.path.join(*([self.storage_group_name, self.virtual_sg_name, str(self.partition_id)]))
        self.assertEqual(expected_prefix_path, ts_file_prefix_path)

    def tearDown(self):
        try:
            os.remove(self.ts_file_path)
        except Exception as e:
            pass
