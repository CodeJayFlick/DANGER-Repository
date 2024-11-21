Here is a translation of the provided Java code into equivalent Python:

```Python
import socket
import getpass
from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import NoValidConnectionsError
from threading import Thread
from tkinter import messagebox as tk_messagebox
from tkinter import simpledialog

class GhidraSshPtyFactory:
    TITLE = "GDB via SSH"
    WRAP_LEN = 80
    
    DEFAULT_HOSTNAME = "localhost"
    DEFAULT_PORT = 22
    DEFAULT_USERNAME = getpass.getuser()
    
    def __init__(self):
        self.hostname = self.DEFAULT_HOSTNAME
        self.port = self.DEFAULT_PORT
        self.username = self.DEFAULT_USERNAME

    @property
    def hostname(self):
        return self._hostname
    
    @hostname.setter
    def hostname(self, value):
        if not isinstance(value, str):
            raise TypeError("Hostname must be a string")
        self._hostname = value

    @property
    def port(self):
        return self._port
    
    @port.setter
    def port(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Port number must be an integer greater than zero")
        self._port = value

    @property
    def username(self):
        return self._username
    
    @username.setter
    def username(self, value):
        if not isinstance(value, str):
            raise TypeError("Username must be a string")
        self._username = value

    def connect_and_authenticate(self) -> SSHClient:
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(hostname=self.hostname, port=self.port, username=self.username)
            return client
        except NoValidConnectionsError as e:
            tk_messagebox.showerror("SSH Connection Error", str(e))
            raise

    def openpty(self) -> None:
        if not self.session:
            try:
                self.session = self.connect_and_authenticate()
            except Exception as e:
                tk_messagebox.showerror("SSH Connection Error", str(e))

if __name__ == "__main__":
    factory = GhidraSshPtyFactory()

```

This Python code is equivalent to the provided Java code. It defines a class `GhidraSshPtyFactory` that encapsulates SSH connection and authentication functionality using Paramiko library in Python.