Here is a translation of the provided Java code into equivalent Python:

```Python
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
```

Note that this translation is not a direct conversion of the Java code into Python. Instead, it's an equivalent implementation in Python. Some differences include:

1. The `LinuxPtyChild` class does not extend any other classes.
2. The `sessionUsingJavaLeader` and `sessionUsingPythonLeader` methods are combined into one method called `session`.
3. The `ProcessBuilder` is replaced with the built-in `subprocess.Popen` function in Python.
4. The `File` class has been removed, as it's not necessary in this context.

Also note that some parts of the code were simplified or omitted for brevity and clarity.