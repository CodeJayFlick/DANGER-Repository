from abc import ABC, abstractmethod
import os
import subprocess
import time
import re

class GdbLinuxSpecimen(ABC):
    @abstractmethod
    def get_command_line(self) -> str:
        pass

    def run_dummy(self) -> dict:
        command = self.get_command_line()
        process = subprocess.Popen(command, shell=True)
        return {"pid": process.pid}

    def get_launcher_args(self) -> dict:
        return {"cmdline_args_name": self.get_command_line()}

    def get_launch_script(self) -> list:
        script = []
        parsed = re.split(r'\s+', self.get_command_line())
        if len(parsed) > 1:
            script.append(f"set args {os.linesep.join(parsed[1:])}")
        script.append(f"file {parsed[0]}")
        script.append("start")
        return script

    def is_running_in(self, process: dict, test: str) -> bool:
        time.sleep(2)
        attributes = process["attributes"]
        if re.search(os.linesep.join(re.split(r'\s+', self.get_command_line())), attributes):
            return True
        else:
            return False

    def is_attachable(self, dummy: dict, attachable: dict, test: str) -> bool:
        time.sleep(2)
        pid = int(attachable["attributes"][GdbModelTargetAttachable.PID_ATTRIBUTE_NAME])
        if pid == dummy["pid"]:
            return True
        else:
            return False

class SLEEP(GdbLinuxSpecimen):
    def get_command_line(self) -> str:
        return "sleep 100000"

class FORK_EXIT(GdbLinuxSpecimen):
    def get_command_line(self) -> str:
        return DummyProc.which("expFork")

class CLONE_EXIT(GdbLinuxSpecimen):
    def get_command_line(self) -> str:
        return DummyProc.which("expCloneExit")

class PRINT(GdbLinuxSpecimen):
    def get_command_line(self) -> str:
        return DummyProc.which("expPrint")

class REGISTERS(GdbLinuxSpecimen):
    def get_command_line(self) -> str:
        return DummyProc.which("expRegisters")

class SPIN_STRIPPED(GdbLinuxSpecimen):
    def get_command_line(self) -> str:
        return DummyProc.which("expSpin.stripped")

class STACK(GdbLinuxSpecimen):
    def get_command_line(self) -> str:
        return DummyProc.which("expStack")
