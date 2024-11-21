import os
import subprocess
from unittest import TestCase


class ImportCsvTestIT(TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test(self):
        os_name = os.environ.get('OS', '').lower()
        if os_name.startswith('windows'):
            self.test_on_windows()
        else:
            self.test_on_unix()

    def test_on_windows(self):
        output = [
            "`````````````````````````````````````````````````",
            "Starting IoTDB Client Import Script",
            "`````````````````````````````````````````````````",
            f"Encounter an error when connecting to server, because {os.error('Connection refused')}"
        ]
        dir_path = self.get_cli_path()
        builder = subprocess.run([
            'cmd.exe',
            '/c',
            os.path.join(dir_path, 'tools', 'import-csv.bat'),
            '-h', '127.0.0.1',
            '-p', '6668',
            '-u', 'root',
            '-pw', 'root',
            '-f', './'
        ], capture_output=True)
        self.test_output(builder.stdout.decode('utf-8').splitlines(), output)

    def test_on_unix(self):
        output = [
            "------------------------------------------",
            "Starting IoTDB Client Import Script",
            "------------------------------------------",
            f"Encounter an error when connecting to server, because {os.error('Connection refused')}"
        ]
        dir_path = self.get_cli_path()
        builder = subprocess.run([
            'sh',
            os.path.join(dir_path, 'tools', 'import-csv.sh'),
            '-h', '127.0.0.1',
            '-p', '6668',
            '-u', 'root',
            '-pw', 'root',
            '-f', './'
        ], capture_output=True)
        self.test_output(builder.stdout.decode('utf-8').splitlines(), output)

    def get_cli_path(self):
        # implement this method to return the cli path
        pass

    def test_output(self, actual, expected):
        # implement this method to compare the actual and expected outputs
        pass


if __name__ == '__main__':
    unittest.main()
