Here is the translation of the Java code to Python:

```Python
import os
import subprocess
import io
from unittest import TestCase


class EnvScriptIT(TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test(self):
        os_name = os.environ['os.name'].lower()
        if os_name.startswith('windows'):
            self.test_start_client_on_windows('.bat', os_name)
        else:
            self.test_start_client_on_unix('.sh', os_name)

    def test_start_client_on_windows(self, suffix, os_name):
        dir_path = self.get_server_path()
        output = "If you want to change this configuration, please check conf/iotdb-env.{}(Unix or OS X, if you use Windows, check conf/iotdb-env.bat).".format(suffix)
        cmd = "{}/conf/iotdb-env{}".format(dir_path, suffix)
        process_builder = subprocess.Popen(['cmd.exe', '/c', cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.test_output(dir_path, suffix, process_builder, output, os_name)

    def test_start_client_on_unix(self, suffix, os_name):
        dir_path = self.get_server_path()
        output = "If you want to change this configuration, please check conf/iotdb-env.{}(Unix or OS X, if you use Windows, check conf/iotdb-env.bat).".format(suffix)
        cmd = "{}/conf/iotdb-env{}".format(dir_path, suffix)
        process_builder = subprocess.Popen(['bash', cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.test_output(cmd, suffix, process_builder, output, os_name)

    def test_output(self, cmd, suffix, process_builder, expected_output, os_name):
        process = process_builder.communicate()[0].decode('utf-8').splitlines()
        for line in process:
            if not line.strip():
                break
        self.assertEqual(expected_output, line)
        process_builder.stdout.close()

    def get_server_path(self):
        user_dir = os.path.expanduser('~')
        target_file = os.path.join(user_dir, 'target', 'maven-archiver', 'pom.properties')
        properties = {}
        if not os.path.exists(target_file):
            return "target/iotdb-server-"
        try:
            with open(target_file) as f:
                for line in f:
                    key, value = line.strip().split('=')
                    properties[key] = value
        except Exception as e:
            pass
        return os.path.join(user_dir, 'target', '{}-{}'.format(properties.get('artifactId'), properties.get('version')))


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@After`. Instead, you can use the setup method provided by the unit test framework.