import os
import subprocess
from unittest import TestCase


class StartClientScriptIT(TestCase):

    def setUp(self):
        self.close_stat_monitor()
        self.env_setup()

    def tearDown(self):
        self.clean_env()

    def test(self):
        os_name = os.environ['os.name'].lower()
        if os_name.startswith('windows'):
            self.test_on_windows()
        else:
            self.test_on_unix()

    def test_on_windows(self):
        cli_path = self.get_cli_path()
        output1 = ["IoTDB> Connection Error, please check whether the network is available or the server has started. Host is 127.0.0.1, port is 6668."]
        command = f"cmd.exe /c {cli_path}sbinstart-cli.bat -h 127.0.0.1 -p 6668 -u root -pw root"
        self.test_output(command, output1)

        output2 = ["Msg: The statement is executed successfully."]
        command = f"cmd.exe /c {cli_path}sbinstart-cli.bat -maxPRC 0 -e \"flush\""
        self.test_output(command, output2)

        output3 = ["IoTDB> error format of max print row count, it should be an integer number"]
        command = f"cmd.exe /c {cli_path}sbinstart-cli.bat -maxPRC -1111111111111111111111111"
        self.test_output(command, output3)

    def test_on_unix(self):
        cli_path = self.get_cli_path()
        output1 = ["IoTDB> Connection Error, please check whether the network is available or the server has started. Host is 127.0.0.1, port is 6668."]
        command = f"sh {cli_path}sbinstart-cli.sh -h 127.0.0.1 -p 6668 -u root -pw root"
        self.test_output(command, output1)

        output2 = ["Msg: The statement is executed successfully."]
        command = f"sh {cli_path}sbinstart-cli.sh -maxPRC 0 -e \"flush\""
        self.test_output(command, output2)

        output3 = ["IoTDB> error format of max print row count, it should be an integer number"]
        command = f"sh {cli_path}sbinstart-cli.sh -maxPRC -1111111111111111111111111"
        self.test_output(command, output3)

    def get_cli_path(self):
        # implement this method to return the cli path
        pass

    def test_output(self, command, expected_outputs):
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        outputs = []
        for line in iter(process.stdout.readline, b''):
            outputs.append(line.decode('utf-8').strip())
        self.assertEqual(outputs, expected_outputs)

    def close_stat_monitor(self):
        # implement this method to close the stat monitor
        pass

    def env_setup(self):
        # implement this method to set up the environment
        pass

    def clean_env(self):
        # implement this method to clean the environment
        pass
