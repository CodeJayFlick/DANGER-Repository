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
