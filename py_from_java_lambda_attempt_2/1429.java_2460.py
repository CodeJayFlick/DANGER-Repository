Here is a translation of the provided Java code into equivalent Python:

```Python
import os
import sys
from typing import List

class LinuxPtySessionLeader:
    def __init__(self):
        self.pty_path = None
        self.sub_args = []

    def parse_args(self, args: List[str]) -> None:
        if len(args) < 1:
            raise Exception("Invalid number of arguments")
        self.pty_path = args[0]
        self.sub_args = args[1:]

    def run(self) -> None:
        try:
            os.setsid()
            fd = os.open(self.pty_path, os.O_RDWR | os.O_CREAT)
            if not isinstance(fd, int):
                raise Exception("Failed to open PTY")

            # Copy stderr to a backup descriptor
            bk_fd = os.dup(2)

            # Duplicate the TTY file descriptor over all standard streams
            os.dup2(fd, 0)
            os.dup2(fd, 1)
            os.dup2(fd, 2)

            try:
                if not isinstance(self.sub_args[0], str):
                    raise Exception("Invalid sub-argument")
                os.execvp(self.sub_args[0], self.sub_args)
            except (OSError, ValueError) as e:
                print(f"Could not execv with args {self.sub_args}: {e}")
                try:
                    os.dup2(bk_fd, 2)
                except OSError as e:
                    sys.exit(-1)
                raise
        except Exception as e:
            Msg.error(self, f"Error: {str(e)}")
```

Please note that Python does not have direct equivalents for Java's `POSIX` and `jnr.posix.POSIXFactory`, so I've replaced them with native Python functions.