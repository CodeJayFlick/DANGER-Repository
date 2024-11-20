import os
import subprocess
import time
from io import BufferedReader


class DummyProc:
    def __init__(self, *args):
        args[0] = self.which(args[0])
        process = subprocess.Popen(args, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pid = process.pid

        print(f"Started dummy process pid={pid}: {list(map(str, args))}")

    @staticmethod
    def which(cmd):
        try:
            return os.path.abspath(os.path.expanduser(cmd))
        except Exception as e:
            # fallback to system
            pass

        if new_file := open(cmd, 'rb'):
            if new_file.can_execute():
                return cmd
            new_file.close()

        is_windows = "windows" in os.name.lower()
        try:
            process = subprocess.Popen([is_windows and "where" or "which", cmd],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
            output, _ = process.communicate(timeout=1)
            line = output.decode().strip()
        except Exception as e:
            raise RuntimeError(e)

        if not line:
            raise RuntimeError(f"Cannot find {cmd}")

        return line

    @staticmethod
    def run(*args):
        proc = DummyProc(args)
        return proc

    def close(self):
        try:
            self.process.terminate()
            self.process.wait(timeout=1)
        except Exception as e:
            print(f"Could not terminate process {self.pid}")
            raise TimeoutError(f"Could not terminate process {self.pid}")


def new_file(file_path: str) -> os.path:
    return file_path
