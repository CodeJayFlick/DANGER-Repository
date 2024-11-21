import logging
from docker import DockerClient
from time import sleep

class ClusterIT:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.default_sg = "root.sg1"

    def get_write_rpc_port(self, container):
        return int(container.get_service_port("iotdb-server_1", 6667))

    def get_write_rpc_ip(self, container):
        return container.get_service_host("iotdb-server_1", 6667)

    def get_read_rpc_ports(self, container):
        return [self.get_write_rpc_port(container)]

    def get_read_rpc_ips(self, container):
        return [self.get_write_rpc_ip(container)]

    def start_cluster(self):
        pass

    @property
    def read_connections(self):
        raise NotImplementedError("Must be implemented in subclass")

    @property
    def write_connection(self):
        raise NotImplementedError("Must be implemented in subclass")
    
    @property
    def session(self):
        raise NotImplementedError("Must be implemented in subclass")

    def init(self):
        self.start_cluster()
        
        container = DockerClient().compose.get_service_port("iotdb-server_1", 6667)
        write_connection = DriverManager.getConnection(f"jdbc:iotdb://{self.get_write_rpc_ip(container)}:{self.get_write_rpc_port(container)}, 'root', 'root'")
        write_statement = write_connection.createStatement()

        read_ports = self.get_read_rpc_ports(container)
        read_ips = self.get_read_rpc_ips(container)
        read_connections = [write_connection for _ in range(len(read_ports))]
        read_statements = [statement for statement in read_connections]
        
        for i, (port, ip) in enumerate(zip(read_ports, read_ips)):
            read_connections[i] = DriverManager.getConnection(f"jdbc:iotdb://{ip}:{port}, 'root', 'root'")
            read_statements[i] = read_connections[i].createStatement()

        self.session = Session.Builder().host(self.get_write_rpc_ip(container)).port(self.get_write_rpc_port(container)).username("root").password("root").enable_cache_leader(False).build()
        self.session.open()
        sleep(3000)

    def clean(self):
        super().clean()


# Usage:
cluster_it = ClusterIT()
try:
    cluster_it.init()
finally:
    cluster_it.clean()
