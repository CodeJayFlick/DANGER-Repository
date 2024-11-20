Here is the equivalent Python code:

```Python
import os
import sys
from io import BufferedReader, StringIO
from typing import List, Optional

class AbstractScript:
    def __init__(self):
        self.command = []
        self.CSV_FILE = "target" + os.sep + "test.csv"

    @staticmethod
    def test_output(builder: dict, output: Optional[List[str]]) -> None:
        builder['redirect_error_stream'] = True
        process = subprocess.Popen(builder['command'], stdout=subprocess.PIPE)
        reader = BufferedReader(StringIO(process.stdout.read().decode('utf-8')))
        actual_output = []
        line = reader.readline()
        while line is not None:
            actual_output.append(line.strip())
            line = reader.readline()

        if output is not None:
            print("should contains:")
            for s in output:
                print(s)
            print("actualOutput:")
            for out in actual_output:
                print(out)

    def get_cli_path(self) -> str:
        user_dir = os.path.expanduser('~')
        target = os.path.join(user_dir, 'cli', f"target{os.sep}maven-archiver{os.sep}pom.properties")
        try:
            with open(target, 'r') as file:
                properties = Properties()
                properties.load(file)
                return os.path.join(os.path.dirname(__file__), 
                                     f"{properties.get('artifactId')}_{properties.get('version')}")
        except FileNotFoundError:
            return "target" + os.sep + "iotdb-cli-"

    def test_method(self, params: Optional[List[str]], output: Optional[List[str]]) -> None:
        basic_params = ["-h", "127.0.0.1", "-p", "6667", "-u", "root", "-pw", "root"]
        self.command.extend(basic_params)
        if params is not None:
            self.command.extend(params)

    @staticmethod
    def read_csv_file(path: str) -> CSVParser:
        return csv.reader(open(path, 'r'))
```

Note that Python does not have a direct equivalent to Java's `CSVFormat` and `ArrayUtils`. Instead, you can use the built-in `csv` module for reading CSV files. Also, I used the `subprocess` module instead of manually creating a process builder as in your original code.