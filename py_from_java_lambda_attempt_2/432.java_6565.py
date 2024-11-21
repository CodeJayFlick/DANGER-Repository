Here is a translation of the Java code into equivalent Python:

```Python
class DbgEngLocalDebuggerModelFactory:
    def __init__(self):
        self.remote = "none"  # Require user to start server
        self.transport = "none"  # Require user to start server

    @property
    def agent_remote_option(self):
        return {"brief": "MS dbgeng.dll (WinDbg) local agent via GADP/TCP",
                "html_details": "Launch a new agent using the Microsoft Debug Engine."}

    @agent_remote_option.setter
    def set_agent_remote(self, value):
        self.remote = value

    @property
    def agent_transport_option(self):
        return {"brief": "Remote process server options (untested)",
                "html_details": "Require user to start server"}

    @agent_transport_option.setter
    def set_agent_transport(self, value):
        self.transport = value

    def is_compatible(self):
        # TODO: Might instead look for the DLL
        return "windows" in sys.platform.lower()

    def get_agent_transport(self):
        return self.transport

    def set_agent_transport(self, transport):
        self.transport = transport

    def get_agent_remote(self):
        return self.remote

    def set_agent_remote(self, remote):
        self.remote = remote

    def get_thread_name(self):
        return "Local dbgeng.dll Agent stdout"

    def get_server_class(self):
        from . import DbgEngGadpServer
        return DbgEngGadpServer

    def complete_command_line(self, cmd):
        cmd.append(str(self.get_server_class()))
        if self.host:
            cmd.extend(["-H", str(self.host)])
        if self.port:
            cmd.extend(["-p", str(self.port)])
        #cmd.extend(["-t", transport])
        if self.remote != "none":
            cmd.extend(["-r", self.remote])
        if self.transport != "none":
            cmd.extend(["-t", self.transport])

# usage
factory = DbgEngLocalDebuggerModelFactory()
print(factory.is_compatible())
```

Please note that Python does not have direct equivalent of Java's `@property` and `@FactoryOption`, so I used a dictionary to represent the property. Also, in Python, we don't need to specify types for variables or method parameters like we do in Java.