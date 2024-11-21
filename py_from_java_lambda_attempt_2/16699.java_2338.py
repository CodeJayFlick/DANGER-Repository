Here is the translation of the Java code to Python:

```Python
import unittest
from io import StringIO
from urllib.parse import urlparse
import os
import tempfile
import mock

class LoadConfigurationTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine_properties_file = 'LoadConfigurationTestEngineProperties'
        cls.cluster_properties_file = 'LoadConfigurationTestClusterProperties'

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(cls.engine_properties_file)
        except FileNotFoundError:
            pass

        try:
            os.remove(cls.cluster_properties_file)
        except FileNotFoundError:
            pass

    @mock.patch('org.apache.iotdb.tsfile.fileSystem.FSFactoryProducer.getFSFactory')
    @unittest.skipIf(os.name != 'posix', "This test is only for Unix-based systems")
    def setUp(self, mock_get_fs_factory):
        self.io_tdb_descriptor = mock.Mock()
        self.cluster_descriptor = mock.Mock()

        with open(self.engine_properties_file, 'w') as f:
            f.write('enable_metric_service=false')

        with open(self.cluster_properties_file, 'w') as f:
            f.write('cluster_rpc_ip=127.0.0.1')

    @unittest.skipIf(os.name != 'posix', "This test is only for Unix-based systems")
    def tearDown(self):
        try:
            os.remove(self.engine_properties_file)
        except FileNotFoundError:
            pass

        try:
            os.remove(self.cluster_properties_file)
        except FileNotFoundError:
            pass

    def test_load_configuration_global(self):
        physical_generator = ClusterPhysicalGenerator()
        load_configuration_operator = LoadConfigurationOperator(LoadConfigurationOperatorType.GLOBAL)

        load_configuration_plan = physical_generator.transform_to_physical_plan(load_configuration_operator)
        metric_properties = load_configuration_plan.get_iotdb_properties()['enable_metric_service']
        self.assertEqual('false', metric_properties)
        cluster_ip = load_configuration_plan.get_cluster_properties()['cluster_rpc_ip']
        self.assertEqual('127.0.0.1', cluster_ip)

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@RunWith` and `@PrepareForTest`. Also, the test cases are written in a way to mimic the behavior of these annotations.