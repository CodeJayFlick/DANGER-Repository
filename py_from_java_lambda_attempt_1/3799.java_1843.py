Here is the translation of the given Java code into equivalent Python:

```Python
import socket
from threading import Thread
from time import sleep

class EclipseConnectorTask:
    def __init__(self, eclipse_service: 'EclipseIntegrationService', port: int):
        self.eclipse_service = eclipse_service
        self.address = "127.0.0.1"
        self.port = port
        self.connection = None

    def run(self) -> None:
        try:
            connection = EclipseConnection(None, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            return
        except ConnectionRefusedError as e:
            # Eclipse may not be started, so we'll try to launch it
            pass

        eclipse_executable_file = self.eclipse_service.get_eclipse_executable_file()
        if eclipse_executable_file is None:
            raise FileNotFoundError("Eclipse executable file not found")

        while True:
            try:
                connection = EclipseConnection(None, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                return
            except ConnectionRefusedError as e:
                # We expect this while Eclipse is not yet initialized
                pass

            sleep(0.5)
            if self.eclipse_service.is_eclipse_feature_installed("ghidradev"):
                break

        print("Failed to connect to Eclipse on port", self.port)

    def get_connection(self) -> 'EclipseConnection':
        return self.connection


class ProcessBuilder:
    def __init__(self, eclipse_executable_file: str):
        self.eclipse_executable_file = eclipse_executable_file
        self.args = ["-data", "/path/to/eclipse/workspace"]

    def start(self) -> None:
        # Code to launch Eclipse process goes here

    @property
    def executable(self) -> str:
        return self.eclipse_executable_file


class EclipseConnection:
    def __init__(self, eclipse_process: 'Process', socket: socket.socket):
        self.eclipse_process = eclipse_process
        self.socket = socket


def create_eclipse_process_builder(eclipse_executable_file: str, eclipse_workspace_dir: str) -> ProcessBuilder:
    process_builder = ProcessBuilder(eclipse_executable_file)
    if eclipse_workspace_dir is not None:
        process_builder.args.append("-data")
        process_builder.args.append(eclipse_workspace_dir)

    return process_builder


def is_ghidra_dev_installed(service: 'EclipseIntegrationService') -> bool:
    try:
        service.is_eclipse_feature_installed("ghidradev")
        return True
    except FileNotFoundError as e:
        return False

```

Note that this translation does not include the entire codebase, but rather focuses on translating the provided Java code into equivalent Python.