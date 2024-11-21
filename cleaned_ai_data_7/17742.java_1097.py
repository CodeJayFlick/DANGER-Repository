import unittest
from io import StringIO
import os
import sys

class IoTDBDescriptorTest(unittest.TestCase):

    def setUp(self):
        self.conf_path = os.environ.get('IOTDB_CONF', None)

    def tearDown(self):
        if self.conf_path:
            os.environ['IOTDB_CONF'] = self.conf_path
        else:
            del os.environ['IOTDB_CONF']

    @unittest.skipIf(sys.version_info < (3, 0), "Only works in Python 3")
    def test_config_url_with_file_protocol(self):
        from iotdb import IoTDBDescriptor

        path_string = 'file:/usr/local/bin'
        os.environ['IOTDB_CONF'] = path_string
        conf_url = IoTDBDescriptor().get_props_url()
        self.assertTrue(conf_url.startswith(path_string))

    @unittest.skipIf(sys.version_info < (3, 0), "Only works in Python 3")
    def test_config_url_with_classpath_protocol(self):
        from iotdb import IoTDBDescriptor

        path_string = 'classpath:/root/path'
        os.environ['IOTDB_CONF'] = path_string
        conf_url = IoTDBDescriptor().get_props_url()
        self.assertTrue(conf_url.startswith(path_string))

    @unittest.skipIf(sys.version_info < (3, 0), "Only works in Python 3")
    def test_config_url_with_plain_file_path(self):
        from iotdb import IoTDBConfig

        path = IoTDBConfig.__file__
        file_path = os.path.abspath(os.path.join(os.path.dirname(path), IoTDBConfig.CONFIG_NAME))
        os.environ['IOTDB_CONF'] = file_path
        conf_url = IoTDBDescriptor().get_props_url()
        self.assertEqual(conf_url, 'file://' + file_path)

if __name__ == '__main__':
    unittest.main()
