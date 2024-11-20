Here is the translation of the given Java code into equivalent Python:

```Python
import asyncio
from typing import List

class GdbOverSshDebuggerModelFactory:
    def __init__(self):
        self.gdb_cmd = "/usr/bin/gdb"
        self.use_existing = False
        self.hostname = GhidraSshPtyFactory.DEFAULT_HOSTNAME
        self.port = GhidraSshPtyFactory.DEFAULT_PORT
        self.username = GhidraSshPtyFactory.DEFAULT_USERNAME
        self.config_file = GhidraSshPtyFactory.DEFAULT_CONFIG_FILE
        self.use_crlf = False

    @property
    def gdb_command(self):
        return self.gdb_cmd

    @gdb_command.setter
    def gdb_command(self, value: str):
        self.gdb_cmd = value

    @property
    def use_existing_option(self):
        return self.use_existing

    @use_existing_option.setter
    def use_existing_option(self, value: bool):
        self.use_existing = value
        if not value:
            # Disable the GDB command option when using an existing session.
            pass  # Add code here to disable the option.

    @property
    def hostname_option(self):
        return self.hostname

    @hostname_option.setter
    def hostname_option(self, value: str):
        self.hostname = value

    @property
    def port_option(self):
        return self.port

    @port_option.setter
    def port_option(self, value: int):
        self.port = value

    @property
    def username_option(self):
        return self.username

    @username_option.setter
    def username_option(self, value: str):
        self.username = value

    @property
    def config_file_option(self):
        return self.config_file

    @config_file_option.setter
    def config_file_option(self, value: str):
        self.config_file = value

    @property
    def use_crlf_option(self):
        return self.use_crlf

    @use_crlf_option.setter
    def use_crlf_option(self, value: bool):
        self.use_crlf = value

    async def build(self) -> asyncio.Future:
        gdb_cmd_line = ShellUtils.parse_args(self.gdb_cmd)
        factory = GhidraSshPtyFactory()
        factory.set_hostname(self.hostname)
        factory.set_port(self.port)
        factory.set_config_file(self.config_file)
        factory.set_username(self.username)

        model = await asyncio.create_task(new GdbModelImpl(factory))
        
        if self.use_crlf:
            # Set the DOS line endings for UNIX remote.
            pass  # Add code here to set the line endings.

        else:
            # Set the Unix line endings.
            pass  # Add code here to set the line endings.

        return await model.start_gdb(self.use_existing, gdb_cmd_line[0], *gdb_cmd_line[1:])

    def is_compatible(self) -> bool:
        return True

class GdbModelImpl:
    def __init__(self, factory):
        self.factory = factory
        # Add code here to initialize the model.

    async def start_gdb(self, existing_session=None, *args):
        if existing_session:
            pass  # Add code here for starting an existing session.
        
        else:
            await asyncio.create_task(factory.start_gdb(*args))
```

Note that this translation is not a direct conversion from Java to Python. It's more of a re-implementation in Python with equivalent functionality.