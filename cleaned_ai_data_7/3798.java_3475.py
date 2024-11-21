import subprocess
import socket

class EclipseConnection:
    def __init__(self):
        self.process = None
        self.socket = None

    def __init__(process=None, socket=None):
        self.process = process
        self.socket = socket

    @property
    def process(self):
        return self._process

    @process.setter
    def process(self, value):
        self._process = value

    @property
    def socket(self):
        return self._socket

    @socket.setter
    def socket(self, value):
        self._socket = value

    def get_process(self):
        return self.process

    def get_socket(self):
        return self.socket
