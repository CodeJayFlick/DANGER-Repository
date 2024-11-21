import os
import subprocess
from io import StringIO


class Pty:
    def __init__(self):
        pass

    def get_parent(self) -> 'PtyParent':
        # Implement this method to return an instance of PtyParent
        raise NotImplementedError("Method not implemented")

    def get_child(self) -> 'PtyChild':
        # Implement this method to return an instance of PtyChild
        raise NotImplementedError("Method not implemented")

    def close(self):
        pass


class PtyParent:
    def __init__(self, parent_fd: int, child_fd: int):
        self.parent_fd = parent_fd
        self.child_fd = child_fd

    def get_parent_fd(self) -> int:
        return self.parent_fd

    def get_child_fd(self) -> int:
        return self.child_fd


class PtyChild:
    def __init__(self, pty_name: str):
        self.pty_name = pty_name

    def session(self, command: str):
        # Implement this method to spawn a new process
        raise NotImplementedError("Method not implemented")

    def get_pty_name(self) -> str:
        return self.pty_name


def openpty() -> Pty:
    # Implement this function to create and return an instance of Pty
    raise NotImplementedError("Method not implemented")


# Example usage:

pty = openpty()
child = pty.get_child()

print(f"Child FD: {child.get_child_fd()}")

writer = os.fdopen(pty.get_parent().get_parent_fd(), 'w')
reader = os.fdopen(pty.get_parent().get_child_fd(), 'r')

writer.write("echo test\n")
writer.flush()

for line in reader:
    print(line.strip())

pty.close()
