import socket
import threading
from io import BufferedReader, BufferedWriter
from os.path import exists, isfile
import platform
import subprocess

class SocketSetupRunnable(threading.Thread):
    def __init__(self, server_socket):
        self.server_socket = server_socket
        super().__init__()

    def run(self):
        while not self.server_socket.close():
            try:
                client_socket, _ = self.server_socket.accept()
                input_stream = BufferedReader(client_socket.makefile('r'))
                output_stream = BufferedWriter(client_socket.makefile('w'))

                line = input_stream.readline().decode('utf-8')
                while line is not None and line != '':
                    command, _, path = line.partition('_')
                    if command == 'open':
                        self.open_in_editor(path)
                    line = input_stream.readline().decode('utf-8')

            except socket.error:
                # Socket was closed
                pass

    def open_in_editor(self, path):
        file_to_open = f"{path}"
        if exists(file_to_open) and isfile(file_to_open):
            platform_name = platform.system()
            if platform_name == 'Windows':
                subprocess.run(['explorer', file_to_open])
            elif platform_name in ['Darwin', 'Linux']:
                subprocess.run(['open', file_to_open])

# Example usage:
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

socket_setup_runnable = SocketSetupRunnable(server_socket)
socket_setup_runnable.start()
