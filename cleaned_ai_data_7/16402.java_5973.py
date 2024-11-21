import os
import sys
from io import StringIO
from contextlib import redirect_stdout

class AbstractScript:
    def test_output(self, builder, output=None):
        f = StringIO()
        with redirect_stdout(f):
            p = builder.start()
            r = open(p.stdout.fileno(), 'r')
            lines = []
            while True:
                line = r.readline().decode('utf-8').strip()
                if not line:
                    break
                lines.append(line)
            r.close()

        print("Process output:")
        for s in lines:
            print(s)

        if output is not None:
            for i, line in enumerate(reversed(lines)):
                assert line == output[i]

    def get_cli_path(self):
        user_dir = os.path.expanduser('~')
        target_file = os.path.join(user_dir, 'target', 'maven-archiver', 'pom.properties')

        if not os.path.exists(target_file):
            return f"target/iotdb-cli-{os.environ.get('USER')}"

        properties = {}
        try:
            with open(target_file, 'r') as file:
                for line in file:
                    key, value = line.strip().split('=')
                    properties[key] = value
        except FileNotFoundError:
            return "target/iotdb-cli-"
        except Exception as e:
            print(f"Error reading pom.properties: {e}")
            return f"target/iotdb-cli-{os.environ.get('USER')}"

        artifact_id = properties['artifactId']
        version = properties['version']

        cli_path = os.path.join(user_dir, 'target', f"{artifact_id}-{version}")

        return cli_path

    def test_on_windows(self):
        pass  # abstract method

    def test_on_unix(self):
        pass  # abstract method
