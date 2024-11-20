import os
import json
from pathlib import Path
import subprocess
import time
import threading

class Environment:
    def __init__(self, name: str, resources: list, downloads: list, skript_target: str, *command_line):
        self.name = name
        self.resources = resources
        self.downloads = downloads
        self.skript_target = skript_target
        self.command_line = command_line

    def get_name(self) -> str:
        return self.name

    def initialize(self, data_root: Path, runner_root: Path, remake: bool):
        env_path = runner_root / self.name
        only_copy_skript = os.path.exists(env_path) and not remake
        
        # Copy Skript to platform
        skript_path = env_path / self.skript_target
        try:
            if not os.path.exists(skript_path.parent):
                os.makedirs(skript_path.parent)
            with open(str(Path(os.getcwd()).resolve().joinpath("main.py")), 'rb') as f, \
                 open(str(skript_path), 'wb') as sf:
                sf.write(f.read())
        except Exception as e:
            print(e)

        if only_copy_skript:
            return

        # Copy resources
        for resource in self.resources:
            source = data_root / resource.source
            target = env_path / resource.target
            try:
                os.makedirs(target.parent)
                with open(str(source), 'rb') as f, \
                     open(str(target), 'wb') as sf:
                    sf.write(f.read())
            except Exception as e:
                print(e)

        # Download additional resources
        for resource in self.downloads:
            url = str(resource.source)
            target = env_path / resource.target
            try:
                with urllib.request.urlopen(url) as response, \
                     open(str(target), 'wb') as f:
                    f.write(response.read())
            except Exception as e:
                print(e)

    def run_tests(self, runner_root: Path, tests_root: Path, dev_mode: bool):
        env_path = runner_root / self.name
        args = ["java", "-ea", "-Dskript.testing.enabled=true",
               f"-Dskript.testing.dir={str(tests_root)}"]
        if not dev_mode:
            args.append(f"-Dskript.testing.devMode=false")
        else:
            args.append("-Dskript.testing.devMode=true")

        process = subprocess.Popen(args, cwd=str(env_path), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        # When we exit, try to make them exit too
        def watchdog():
            time.sleep(8 * 60)
            if process.poll() is None:
                print("Test environment is taking too long, failing...")
                os._exit(1)

        threading.Thread(target=watchdog).start()

        code = process.wait()
        if code != 0:
            raise Exception(f"environment returned with code {code}")

        # Read test results
        try:
            with open(str(env_path / "test_results.json"), 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print("No test results found")
