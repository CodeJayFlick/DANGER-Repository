import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class GdbGadpServer:
    def __init__(self):
        self.gdb_cmd = "gdb"
        self.gdb_args = []
        self.bind_to = None

    @staticmethod
    def main(args):
        try:
            runner = Runner()
            runner.run(args)
        except Exception as e:
            print(f"Error: {e}")
            exit(1)

    @classmethod
    def new_instance(cls, addr):
        return GdbGadpServerImpl(addr)


class Runner:
    def __init__(self):
        self.gdb_cmd = "gdb"
        self.gdb_args = []
        self.bind_to = None

    def run(self, args):
        self.parse_arguments(args)

        try:
            server = GdbGadpServer.new_instance(self.bind_to)
            with ThreadPoolExecutor() as executor:
                future = executor.submit(server.start_gdb, self.gdb_cmd, self.gdb_args)
                result = future.result()
                if not result:
                    print("Error starting GDB/GADP")
                    exit(-1)

            agent_window = AgentWindow("GDB Agent for Ghidra", server.get_local_address())
            server.console_loop()

        except Exception as e:
            print(f"Error: {e}")
            exit(0)


    def parse_arguments(self, args):
        iface = "localhost"
        port = 12345
        ait = iter(args)
        while ait:
            a = next(ait)
            if "--gadp-args".equals(a):
                break

            elif "-h" == a or "--help".equals(a):
                self.print_usage()
                exit(0)

            else:
                self.gdb_args.append(a)

        while ait:
            a = next(ait)
            if "-p" == a or "--port".equals(a):
                port_str = next(ait)
                try:
                    port = int(port_str)
                except ValueError as e:
                    print(f"Invalid port: {e}")
                    self.print_usage()
                    exit(-1)

            elif "-H" == a or "--host".equals(a):
                iface = next(ait)

            elif "-g" == a or "--gdb-cmd".equals(a):
                self.gdb_cmd = next(ait)

            elif "-x" == a or "--existing".equals(a):
                self.gdb_cmd = None

            else:
                print(f"Unknown option: {a}")
                self.print_usage()
                exit(-1)

        self.bind_to = socket.gethostbyname(iface) + ":" + str(port)


    def print_usage(self):
        print("This is the GADP wrapper for GDB. Usage:")
        print()

        print("gadpgdb [GDB options] [--gadp-args [-H HOST/ADDR] [-p PORT] [-g CMD] [-x]]")
        print()

        print("Options:")
        print()
        print("--host/-H          The address of the interface on which to listen. Default is localhost")
        print("--port/-p          The TCP port on which to listen. Default is 12345. 0 for automatic.")
        print("--gdb-cmd/-g       The command to launch gdb. Default is 'gdb'")
        print("--existing/-x      Do not launch gdb. Instead just open a pty")
        print()

        print("Starts a GDB-based GADP server \"agent\". In general, it can be invoked in the same manner as standard gdb.")
        print()


class AgentWindow:
    def __init__(self, title, address):
        self.title = title
        self.address = address


class GdbGadpServerImpl(GdbGadpServer):
    pass

    # Start the GDB session
    def start_gdb(self, gdb_cmd, args):
        # TO DO: implement this method
        return None

    # Get the local address to which the SCTL server is bound.
    def get_local_address(self):
        return self.bind_to

    # Starts the GDB manager's console loop
    def console_loop(self):
        pass


# Start a new instance of the GdbGadpServer with an existing socket address
def start_gdb_server(addr):
    return GdbGadpServer.new_instance(addr)


if __name__ == "__main__":
    main(sys.argv[1:])
