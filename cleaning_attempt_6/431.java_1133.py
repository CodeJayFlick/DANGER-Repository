import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class DbgEngGadpServer:
    DEFAULT_DBGSRV_TRANSPORT = "tcp:port=11200"

    def __init__(self):
        self.bind_to = None
        self.dbgeng_args = []
        self.bus_id = 1
        self.debug_srv_transport = self.DEFAULT_DBGSRV_TRANSPORT
        self.remote = None

    @staticmethod
    def main(args):
        try:
            DbgEngGadpServer().run(args)
        except Exception as e:
            logging.error("Error starting dbgeng/GADP", exc_info=e)
            exit(-1)

    @classmethod
    def new_instance(cls, addr):
        return cls(addr)

    def run(self, args):
        self.parse_arguments(args)

        try:
            with ThreadPoolExecutor() as executor:
                future = executor.submit(lambda: self.start_dbg_eng(self.dbgeng_args))
                result = future.result()
                if not result:
                    logging.error("Error starting dbgeng/GADP")
                    exit(-1)
                else:
                    print(f"DbgEngGadpServer started successfully.")
        except Exception as e:
            logging.error("Error running DbgEngGadpServer", exc_info=e)

    def parse_arguments(self, args):
        self.bind_to = socket.gethostbyname('localhost')
        port = 12345
        for arg in args:
            if arg == "-h" or arg == "--help":
                print_usage()
                exit(0)
            elif arg.startswith("-p") or arg.startswith("--port"):
                try:
                    port = int(arg.split("=")[1])
                except ValueError as e:
                    logging.error("Invalid port number")
                    print_usage()
                    exit(-1)
            elif arg.startswith("-H") or arg.startswith("--host"):
                self.bind_to = socket.gethostbyname(arg.split("=")[1])
            elif arg.startswith("-i") or arg.startswith("--bus-id"):
                try:
                    self.bus_id = int(arg.split("=")[1])
                except ValueError as e:
                    logging.error("Invalid bus ID")
                    print_usage()
                    exit(-1)
            elif arg.startswith("-t") or arg.startswith("--transport"):
                self.debug_srv_transport = arg
                self.dbgeng_args.append(self.debug_srv_transport)
            elif arg.startswith("-r") or arg.startswith("--remote"):
                self.remote = arg
                self.dbgeng_args.append(self.remote)

    def start_dbg_eng(self, args):
        # Start the dbgeng manager's console loop here.
        pass

    @property
    def local_address(self):
        return self.bind_to

    def terminate(self):
        # Close all connections and ports, GADP and Process Server, and terminate the server.
        pass

    @property
    def is_running(self):
        # Check if the server is running here. This will return false: 1) Before the server has been started,
        # 2) After a call to `terminate()`, or 3) When an error occurs causing the server to terminate unexpectedly.
        pass

def print_usage():
    print("This is the GADP server for Windows dbgeng.dll. Usage:")
    print()
    print("[-H HOST/ADDR] [-p PORT] [-i ID] [-t TRANSPORT] [-r REMOTE]")
    print()
    print("Options:")
    print("  --host/-H          The address of the interface on which to listen.")
    print("                     Default is localhost")
    print("  --port/-p          The TCP port on which to listen for GADP. Default is 12345")
    print("  --bus-id/-i        The numeric client id for synthetic requests. Default is 1")
    print("  --transport/-t     The transport specification for the Process Server.")
    print("                     Default is tcp:port=11200")
    print("  --remote/-r        The transport specification for a remote server.")

if __name__ == "__main__":
    DbgEngGadpServer.main(sys.argv[1:])
