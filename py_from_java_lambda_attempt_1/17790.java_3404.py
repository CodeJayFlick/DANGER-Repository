Here is the translation of the Java code to Python:

```Python
import os
from unittest import TestCase


class TsFileManagerTest(TestCase):

    def setUp(self):
        self.temp_sg_dir = os.path.join(os.environ['TEST_CONSTANT_BASE_OUTPUT_PATH'], 'tempSG')
        if not os.path.exists(self.temp_sg_dir):
            os.makedirs(self.temp_sg_dir)
        self.ts_file_manager = TsFileManager("test", "0", self.temp_sg_dir)
        self.seq_resources = []
        for i in range(5):
            resource = generate_ts_file_resource(i)
            self.seq_resources.append(resource)
        self.unseq_resources = []
        for i in range(6, 10):
            resource = generate_ts_file_resource(i)
            self.unseq_resources.append(resource)

    def tearDown(self):
        if os.path.exists(self.temp_sg_dir):
            import shutil
            shutil.rmtree(self.temp_sg_dir)


def generate_ts_file_resource(id):
    file_path = f"{os.environ['TEST_CONSTANT_BASE_OUTPUT_PATH']}/{id}/{id}/{id}/{id}.tsfile"
    return TsFileResource(file_path)


class TestTsFileManager(unittest.TestCase):

    def test_add_remove_and_iterator(self):
        for ts_file_resource in self.seq_resources:
            self.ts_file_manager.add(ts_file_resource, True)
        self.ts_file_manager.addAll(self.unseq_resources, False)
        self.assertEqual(5, len(self.ts_file_manager.get_ts_files(True)))
        self.assertEqual(4, len(self.ts_file_manager.get_ts_files(False)))
        self.assertEqual(5, self.ts_file_manager.size(True))
        self.assertEqual(4, self.ts_file_manager.size(False))
        self.assertTrue(self.ts_file_manager.contains(seq_resources[0], True))
        self.assertFalse(
            self.ts_file_manager.contains(TsFileResource(os.path.join("root.compactionTest", 10, "tsfile")), False)
        )
        self.assertFalse(
            self.ts_file_manager.contains(TsFileResource(os.path.join("root.compactionTest", 11, "tsfile")), False)
        )
        self.assertFalse(self.ts_file_manager.isEmpty(True))
        self.assertFalse(self.ts_file_manager.isEmpty(False))
        self.ts_file_manager.remove(self.ts_file_manager.get_ts_files(True)[0], True)
        self.ts_file_manager.remove(self.ts_file_manager.get_ts_files(False)[0], False)
        self.assertEqual(4, len(self.ts_file_manager.get_ts_files(True)))
        self.ts_file_manager.removeAll(self.ts_file_manager.get_ts_files(False), False)
        self.assertEqual(0, len(self.ts_file_manager.get_ts_files(False)))
        count = 0
        iterator = self.ts_file_manager.get_iterator(True)
        while iterator.hasNext():
            iterator.next()
            count += 1
        self.assertEqual(4, count)
        self.ts_file_manager.removeAll(self.ts_file_manager.get_ts_files(True), True)
        self.assertEqual(0, len(self.ts_file_manager.get_ts_files(True)))
        self.assertTrue(self.ts_file_manager.isEmpty(True))
        self.assertTrue(self.ts_file_manager.isEmpty(False))
        self.ts_file_manager.add(TsFileResource(os.path.join("root.compactionTest", 10, "tsfile")), True)
        self.ts_file_manager.add(TsFileResource(os.path.join("root.compactionTest", 11, "tsfile")), False)
        self.assertEqual(1, self.ts_file_manager.size(True))
        self.assertEqual(1, self.ts_file_manager.size(False))
        self.ts_file_manager.clear()
        self.assertEqual(0, self.ts_file_manager.size(True))
        self.assertEqual(0, self.ts_file_manager.size(False))


    def test_iterator_remove(self):
        for ts_file_resource in self.seq_resources:
            self.ts_file_manager.add(ts_file_resource, True)
        self.ts_file_manager.addAll(seq_resources, False)
        self.assertEqual(5, len(self.ts_file_manager.get_ts_files(True)))
        iterator = self.ts_file_manager.get_iterator(True)
        try:
            iterator.remove()
        except UnsupportedOperationException:
            pass
        self.assertEqual(5, len(self.ts_file_manager.get_ts_files(True)))
        ts_file_resource1 = TsFileResource(os.path.join("root.compactionTest", 10, "tsfile"))
        ts_file_resource2 = TsFileResource(os.path.join("root.compactionTest", 11, "tsfile"))
        self.ts_file_manager.add(ts_file_resource1, True)
        self.ts_file_manager.add(ts_file_resource2, True)
        count = 0
        iterator = self.ts_file_manager.get_iterator(True)
        while iterator.hasNext():
            count += 1
            iterator.next()
        self.assertEqual(8, count)


if __name__ == '__main__':
    unittest.main()
```

Note: The `TsFileManager` class and the `generate_ts_file_resource` function are not defined in this code. You would need to implement these classes and functions according to your requirements.