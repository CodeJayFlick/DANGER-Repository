Here is the equivalent Python code:

```Python
import unittest
from io import IOError
from typing import List

class GetAllDevicesTest(unittest.TestCase):

    def setUp(self):
        self.conf = TSFileConfig(TSFileDescriptor.getInstance().getConfig())
        self.max_degree_of_index_node = self.conf.get_max_degree_of_index_node()
        self.file_path = FileGenerator.output_data_file

    def tearDown(self):
        FileGenerator.after()
        self.conf.set_max_degree_of_index_node(self.max_degree_of_index_node)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), "This test requires Python 3.5 or later")
    def test_get_all_devices1(self):
        self.test_get_all_devices(2, 2)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), "This test requires Python 3.5 or later")
    def test_get_all_devices2(self):
        self.test_get_all_devices(2, 50)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), "This test requires Python 3.5 or later")
    def test_get_all_devices3(self):
        self.test_get_all_devices(50, 2)

    @unittest.skipIf(not hasattr(unittest, 'assertEqual'), "This test requires Python 3.5 or later")
    def test_get_all_devices4(self):
        self.test_get_all_devices(50, 50)

    def test_get_all_devices(self, device_num: int, measurement_num: int) -> None:
        FileGenerator.generate_file(10000, device_num, measurement_num)
        try:
            file_reader = TsFileSequenceReader(self.file_path)
            devices = file_reader.get_all_devices()
            self.assertEqual(device_num, len(devices))
            for i in range(device_num):
                self.assertTrue(f"d{i}" in devices)

        except IOError as e:
            raise

if __name__ == '__main__':
    unittest.main()
```

Please note that the above Python code is equivalent to the Java code provided. However, it may not be exactly identical due to differences between languages and their respective libraries.