Here is the translation of the Java code into Python:

```Python
import unittest
from datetime import datetime as dt

class Test(unittest.TestCase):

    def test_full_selection(self):
        seq_resources = []
        unseq_resources = []

        for i in range(4):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        for i in range(4):
            file_name = f"0{10}seq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            seq_resources.append(ts_file_resource)

        merge_file_selector = MaxFileMergeFileSelector(CrossSpaceMergeResource(seq_resources, unseq_resources), Long.MAX_VALUE)
        result = merge_file_selector.select()
        self.assertEqual(len(result[0]), len(seq_resources))
        self.assertEqual(len(result[1]), len(unseq_resources))

    def test_non_selection(self):
        seq_resources = []
        unseq_resources = []

        for i in range(4):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        for i in range(4):
            file_name = f"0{10}seq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            seq_resources.append(ts_file_resource)

        merge_file_selector = MaxFileMergeFileSelector(CrossSpaceMergeResource(seq_resources, unseq_resources), 1)
        result = merge_file_selector.select()
        self.assertEqual(len(result), 0)

    def test_restricted_selection(self):
        seq_resources = []
        unseq_resources = []

        for i in range(4):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        for i in range(4):
            file_name = f"0{10}seq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            seq_resources.append(ts_file_resource)

        merge_file_selector = MaxFileMergeFileSelector(CrossSpaceMergeResource(seq_resources, unseq_resources), 400000)
        result = merge_file_selector.select()
        self.assertEqual(len(result[0]), len(seq_resources[:4]))
        self.assertEqual(len(result[1]), len(unseq_resources[:4]))

    def test_file_open_selection(self):
        seq_resources = []
        unseq_resources = []

        for i in range(4):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        for i in range(4):
            file_name = f"0{10}seq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            seq_resources.append(ts_file_resource)

        large_unseq_ts_file_resource = unseq_resources[3]
        large_unseq_ts_file_resource.set_closed(False)
        for device in large_unseq_ts_file_resource.get_devices():
            time_index.update_start_time(device, large_unseq_ts_file_resource.get_start_time(device))

        merge_file_selector = MaxFileMergeFileSelector(CrossSpaceMergeResource(seq_resources + [large_unseq_ts_file_resource], unseq_resources), Long.MAX_VALUE)
        result = merge_file_selector.select()
        self.assertEqual(len(result), 0)

    def test_file_open_selection_from_compaction(self):
        seq_resources = []
        unseq_resources = []

        for i in range(4):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        for i in range(4):
            file_name = f"0{10}seq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            seq_resources.append(ts_file_resource)

        large_unseq_ts_file_resource = unseq_resources[3]
        large_unseq_ts_file_resource.set_closed(False)
        for device in large_unseq_ts_file_resource.get_devices():
            time_index.update_start_time(device, large_unseq_ts_file_resource.get_start_time(device))

        ttl_lower_bound = dt.now().timestamp() - Long.MAX_VALUE
        merge_resource = CrossSpaceMergeResource(seq_resources + [large_unseq_ts_file_resource], unseq_resources, ttl_lower_bound)
        self.assertEqual(5, len(merge_resource.get_seq_files()))
        self.assertEqual(1, len(merge_resource.get_unseq_files()))

    def test_selection_about_last_seq_file(self):
        seq_resources = []
        unseq_resources = []

        for i in range(4):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        for i in range(4):
            file_name = f"0{10}seq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            seq_resources.append(ts_file_resource)

        large_unseq_ts_file_resource = unseq_resources[2]
        large_unseq_ts_file_resource.set_closed(False)
        for device in large_unseq_ts_file_resource.get_devices():
            time_index.update_start_time(device, large_unseq_ts_file_resource.get_start_time(device))

        merge_file_selector = MaxFileMergeFileSelector(CrossSpaceMergeResource(seq_resources + [large_unseq_ts_file_resource], unseq_resources), Long.MAX_VALUE)
        result = merge_file_selector.select()
        self.assertEqual(2, len(result[0]))
        seq_resources.clear()

    def test_select_continuous_unseq_file(self):
        seq_resources = []
        unseq_resources = []

        for i in range(100):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        for i in range(100):
            file_name = f"0{10}seq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            seq_resources.append(ts_file_resource)

        unseq_list = [unseq_resources[2]]
        for i in range(100):
            file_name = f"0{10}unseq-{i}-{i}-0.tsfile"
            ts_file_resource = TsFileResource(file_name)
            ts_file_resource.set_closed(True)
            prepare_file(ts_file_resource, 0, 1, 0)
            unseq_resources.append(ts_file_resource)

        resource = CrossSpaceMergeResource(seq_list[99:], unseq_list[:3])
        merge_file_selector = MaxFileMergeFileSelector(resource, Long.MAX_VALUE)
        result = merge_file_selector.select()
        self.assertEqual(2, len(result))
        seq_resources.clear()

    def test_remove_files(self):
        pass

if __name__ == '__main__':
    unittest.main()