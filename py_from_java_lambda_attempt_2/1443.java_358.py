Here is the translation of the given Java code into equivalent Python:

```Python
import time
from paramiko import Channel

class SshPtySession:
    def __init__(self, channel):
        self.channel = channel

    def wait_exited(self) -> int | None:
        while not self.channel.exit_status_ready():
            time.sleep(1)
        return self.channel.recv_exit_status()

    def destroy_forcibly(self):
        self.channel.close()
```

Please note that Python does not have a direct equivalent of Java's `Channel` class. The `paramiko` library is used here to simulate the behavior of a channel in SSH connections.

The `wait_exited` method waits until the remote process has finished executing and then returns its exit status. It uses the `exit_status_ready()` method to check if the remote process has finished, and the `recv_exit_status()` method to get the actual exit status.

The `destroy_forcibly` method closes the channel forcibly, effectively terminating any ongoing SSH connection.