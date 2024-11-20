from abc import ABC, abstractmethod
import os
import subprocess
import re
import threading

class WindowsSpecimen(ABC):
    @abstractmethod
    def get_command_line(self) -> str:
        pass

    def run_dummy(self) -> 'DummyProc':
        return DummyProc.run(subprocess.list2cmdline([self.get_command_line()]))

    def get_launcher_args(self) -> dict:
        return {'CMDLINE_ARGS_NAME': self.get_command_line()}

    def get_launch_script(self) -> list:
        return [f'.create {self.get_command_line()} ; g']

class DummyProc:
    @staticmethod
    def run(args):
        # This is not great, but.... 
        process = subprocess.Popen(args)
        process.wait()

class WindowsSpecimen(PRINT, NOTEPAD, CREATE_PROCESS, CREATE_THREAD_EXIT, REGISTERS, STACK):

    PRINT = lambda: WindowsSpecimen(get_command_line=lambda: DummyProc.which("expPrint.exe"))
    NOTEPAD = lambda: WindowsSpecimen(get_command_line=lambda: "C:\\Windows\\notepad.exe")
    CREATE_PROCESS = lambda: WindowsSpecimen(get_command_line=lambda: DummyProc.which("expCreateProcess.exe"))
    CREATE_THREAD_EXIT = lambda: WindowsSpecimen(get_command_line=lambda: DummyProc.which("expCreateThreadExit.exe"))
    REGISTERS = lambda: WindowsSpecimen(get_command_line=lambda: DummyProc.which("expRegisters.exe"))
    STACK = lambda: WindowsSpecimen(get_command_line=lambda: DummyProc.which("expStack.exe"))

    def get_short_name(self, full_path):
        if not full_path:
            return None
        return os.path.basename(full_path)

    def get_bin_module_key(self) -> str:
        module_name = self.get_bin_module_name()
        if module_name.endswith(".exe"):
            return module_name[:-4]
        return module_name

    def get_bin_module_name(self):
        return self.get_short_name(subprocess.list2cmdline([self.get_command_line()])[0])

    def is_running_in(self, process: str, test) -> bool:
        expected = self.get_bin_module_name()
        modules = [m for m in os.listdir(process) if re.match(expected.lower(), m)]
        return any(module == expected

    def wait_on(self):
        threading.Thread(target=lambda: None).start()

    def is_attachable(self, dummy: DummyProc, attachable: str, test) -> bool:
        self.wait_on()
        pid = int(subprocess.check_output(f"tasklist | findstr {attachable}").decode().split()[-1])
        return pid == dummy.pid
