import os
import threading

class LocalProcessPtySession:
    def __init__(self, process):
        self.process = process
        print(f"local Pty session. PID = {process.pid()}")

    def wait_exited(self):
        try:
            return self.process.wait()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"Error: {e}")
            return None

    def destroy_forcibly(self):
        try:
            self.process.terminate()
        except Exception as e:
            print(f"Error: {e}")

# Example usage:

process = os.popen("your_command_here", "r")
pty_session = LocalProcessPtySession(process)
