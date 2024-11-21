import os
from typing import Dict, List

class MacOSSpecimen:
    def __init__(self):
        pass

    @staticmethod
    def get_command_line(specimen: str) -> str:
        if specimen == "SPIN":
            return DummyProc.which("expSpin")
        elif specimen == "FORK_EXIT":
            return DummyProc.which("expFork")
        elif specimen == "CLONE_EXIT":
            return DummyProc.which("expCloneExit")
        elif specimen == "PRINT":
            return DummyProc.which("expPrint")
        elif specimen == "REGISTERS":
            return DummyProc.which("expRegisters")
        elif specimen == "STACK":
            return DummyProc.which("expStack")
        elif specimen == "CREATE_PROCESS":
            return DummyProc.which("expCreateProcess")
        elif specimen == "CREATE_THREAD_EXIT":
            return DummyProc.which("expCreateThreadExit")

    @staticmethod
    def run_dummy(specimen: str) -> Dict:
        dummy = DummyProc.run(MacOSSpecimen.get_command_line(specimen).split())
        return {"dummy": dummy}

    @staticmethod
    def get_launcher_args() -> Dict:
        return {"args": MacOSSpecimen.get_command_line("SPIN")}

    @staticmethod
    def get_launch_script() -> List:
        return [".create " + MacOSSpecimen.get_command_line("SPIN") + "; g"]

    @staticmethod
    def get_short_name(full_path: str) -> str:
        if full_path is None:
            return None
        return os.path.basename(full_path)

    @staticmethod
    def get_bin_module_key() -> str:
        module_name = MacOSSpecimen.get_bin_module_name()
        if module_name.endswith(".exe"):
            return module_name[:-4]
        return module_name

    @staticmethod
    def get_bin_module_name() -> str:
        return MacOSSpecimen.get_short_name(MacOSSpecimen.get_command_line("SPIN").split()[0])

    @staticmethod
    def is_running_in(process: dict, test: Dict) -> bool:
        expected = process["name"]
        session = process["session"]
        modules = [module for module in session.values() if isinstance(module, dict)]
        return any([module_name.lower().startswith(expected.lower()) for module_name in (module.get("name") for module in modules)])

    @staticmethod
    def is_attachable(dummy: Dict, attachable: Dict, test: Dict) -> bool:
        wait_on(attachable["attributes"])
        pid = attachable.get("pid", -1)
        return pid == dummy["pid"]

class DummyProc:
    @staticmethod
    def which(command: str) -> str:
        # implement this method to simulate the behavior of "which" command in Unix shell.
        pass

if __name__ == "__main__":
    specimen = MacOSSpecimen()
    print(specimen.get_command_line("SPIN"))
