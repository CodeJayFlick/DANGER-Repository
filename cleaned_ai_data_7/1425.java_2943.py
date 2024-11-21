import os
import subprocess
from urllib.parse import unquote_to_bytes
from pathlib import Path


class LinuxPtyChild:
    def __init__(self, fd, name):
        self.name = name

    def null_session(self):
        return self.name

    def session(self, args, env=None):
        if not env:
            env = {}
        java_command = f"{os.environ['JAVA_HOME']}/bin/java"
        process_args = [java_command, "-cp", os.environ["JAVAClassPath"], "LinuxPtySessionLeader"]
        process_args.append(str(self.name))
        process_args.extend(args)
        builder = subprocess.Popen([*process_args], env=env, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            return LocalProcessPtySession(builder.stdout.fileno())
        except Exception as e:
            print(f"Could not start process with args {args}: {e}")
            raise


class LocalProcessPtySession:
    def __init__(self, fd):
        self.fd = fd

    # Other methods...
