import socket
from getpass import getuser
import ssl
import xml.etree.ElementTree as ET

class ServerConnectTask:
    def __init__(self, server_info: dict, allow_login_retry: bool):
        self.server = server_info
        self.allow_login_retry = allow_login_retry

    def run(self) -> None:
        try:
            # Get the repository handle
            hdl = get_repository_server_handle(self.server)
        except Exception as e:
            exc = e
        finally:
            pass

    def get_exception(self):
        return exc

    def get_repository_server_handle(self, server_info: dict) -> dict or None:
        try:
            # Test SSL Handshake to ensure that user is able to decrypt keystore.
            test_server_ssl_connection(server_info)
            
            reg = Registry()
            gsh = GhidraServerHandle(reg, self.server['server_name'], self.server['port_number'])
            return gsh.get_repository_server_handle(get_local_user_subject(), callbacks)

        except Exception as e:
            if is_ssl_handshake_cancelled(e):
                return None
            raise e

    def get_ghidra_server_handle(self) -> dict or None:
        try:
            # Get the Ghidra Server Handle object
            gsh = get_ghidra_server_handle(self.server)
            return gsh

        except Exception as e:
            if is_ssl_handshake_cancelled(e):
                return None
            raise e


def test_server_ssl_connection(server_info: dict) -> None:
    port_factory = RMIServerPortFactory()
    factory = SslRMIClientSocketFactory()
    server_name = server_info['server_name']
    ssl_rmi_port = port_factory.get_rmi_ssl_port()

    try:
        with socket.create_connection((server_name, ssl_rmi_port)) as sock:
            # Complete SSL handshake to trigger client keystore access if required
            sock.start_handshake()

    except Exception as e:
        raise e


def get_local_user_subject() -> dict or None:
    username = getuser()
    pset = set([GhidraPrincipal(username)])
    subj = Subject(false, pset)
    return subj

def is_ssl_handshake_cancelled(e: Exception) -> bool:
    if isinstance(e, ssl.SSLError):
        # Check for specific SSL errors
        pass  # TO DO: Translate this part into Python
    return False


class GhidraServerHandle:
    def __init__(self, reg: Registry, server_name: str, port_number: int) -> None:
        self.reg = reg
        self.server_name = server_name
        self.port_number = port_number

    def get_repository_server_handle(self, subject: dict or None, callbacks: list) -> dict or None:
        # TO DO: Translate this part into Python


def check_server_bind_names(reg: Registry) -> None:
    required_version = "4.3.x (or older)"
    
    reg_list = reg.list()
    bad_ver_count = 0

    for name in reg_list:
        if name == GhidraServerHandle.BIND_NAME:
            return
        elif name.startswith(GhidraServerHandle.BIND_NAME_PREFIX):
            version = name[len(GhidraServerHandle.BIND_NAME_PREFIX):]
            exc = Exception(f"Incompatible Ghidra Server interface, detected interface version {version}, this client requires server version {required_version}")
            bad_ver_count += 1
        else:
            raise Exception("Ghidra Server not found.")
    if bad_ver_count > 0:
        raise Exception(f"Multiple incompatible versions of the Ghidra Server were found: {bad_ver_count}")


class RMIServerPortFactory:
    def __init__(self, port_number: int) -> None:
        self.port_number = port_number

    def get_rmi_ssl_port(self) -> int:
        return self.port_number


def main():
    server_info = {"server_name": "localhost", "port_number": 1099}
    allow_login_retry = True
    task = ServerConnectTask(server_info, allow_login_retry)
    task.run()

if __name__ == "__main__":
    main()
