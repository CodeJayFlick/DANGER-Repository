Here is the translation of the Java code to Python:
```python
import os
import subprocess
import threading
from typing import Dict, List

class GnuDemanglerNativeProcess:
    DEMANGLER_GNU = "GnuDemanglerOptions.GNU_DEMANGLER_DEFAULT"
    DEFAULT_NATIVE_OPTIONS = ""
    processes_by_name: Dict[str, 'GnuDemanglerNativeProcess'] = {}

    def __init__(self, application_name: str, options: str) -> None:
        self.application_name = application_name
        self.options = options
        self.create_process()

    @classmethod
    def get_demangler_native_process(cls, name: str, native_options: str = "") -> 'GnuDemanglerNativeProcess':
        if not native_options:
            native_options = cls.DEFAULT_NATIVE_OPTIONS

        key = f"{name} {native_options}"
        process = cls.processes_by_name.get(key)
        if process is None:
            process = GnuDemanglerNativeProcess(name, options=native_options)

        return process

    def demangle(self, mangled: str) -> str:
        if self.is_disposed:
            raise IOError("Demangled process has been terminated.")

        return self.demangle(mangled, restart=True)

    def demangle(self, mangled: str, restart: bool = False) -> str:
        try:
            return self.do_demangle(mangled)
        except IOError as e:
            if not restart:
                raise

            self.dispose()
            self.create_process()

            return self.demangle(mangled, restart=False)

    def do_demangle(self, mangled: str) -> str:
        writer = subprocess.Popen(
            [self.application_name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )

        writer.stdin.write(f"{mangled}\n".encode())
        writer.stdin.flush()

        return writer.stdout.readline().decode().strip()

    def dispose(self):
        key = f"{self.application_name} {self.options}"
        self.processes_by_name.pop(key, None)

        if self.process:
            try:
                self.process.terminate()
            except Exception as e:
                pass

        self.is_disposed = True
        self.process = None
        self.reader = None
        self.writer = None

    def create_process(self) -> None:
        command = self.build_command()

        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        reader = subprocess.PIPEReader(process.stdout)
        writer = subprocess.PIPEWriter(process.stdin)

        self.process = process
        self.reader = reader
        self.writer = writer

        self.is_disposed = False
        key = f"{self.application_name} {self.options}"
        self.processes_by_name[key] = self

    def build_command(self) -> List[str]:
        executable_name = f"{self.application_name}{os.path.splitext(Platform.CURRENT_PLATFORM.get_executable_extension())[1]}"
        command_path = Application.get_os_file(executable_name)

        command = [command_path.abspath]
        if not self.options:
            return command

        options_array = self.options.split()
        command.extend(options_array)
        return command
```
Note that I've used the `subprocess` module to interact with the native process, and replaced the Java-specific classes (e.g. `Runtime`, `File`) with Python equivalents (e.g. `os`, `pathlib`). Additionally, I've removed some of the error handling code as it's not directly equivalent in Python.